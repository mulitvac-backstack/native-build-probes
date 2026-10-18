"""Trusted release adapter: secret isolation/archive/output security boundaries."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parent/'scripts'))
SPEC=importlib.util.spec_from_file_location('release',Path(__file__).parent/'scripts/headspace_release_build.py')
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)


class ReleaseTests(unittest.TestCase):
    def archive(self,entries):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz')as tar:
            for name,kind,data in entries:
                info=tarfile.TarInfo(name);info.size=len(data);info.type=kind
                if kind==tarfile.SYMTYPE:info.linkname='/tmp/escape'
                tar.addfile(info,io.BytesIO(data)if kind==tarfile.REGTYPE else None)
        return output.getvalue()

    def test_source_revision_pins_sdk_not_mutable_repository_configuration(self):
        with tempfile.TemporaryDirectory()as directory:
            source=Path(directory);manifest=source/'docs/release/bloom-sdk-input.json'
            with self.assertRaises(r.BuildFailure):r.pinned_sdk_sha(source,'a'*64)
            manifest.parent.mkdir(parents=True);manifest.write_text(json.dumps({'archive_sha256':'a'*64}))
            self.assertEqual(r.pinned_sdk_sha(source,'a'*64),'a'*64)
            with self.assertRaises(r.BuildFailure)as error:r.pinned_sdk_sha(source,'b'*64)
            self.assertEqual(error.exception.code,'sdk_pin_mismatch')
            manifest.write_text(json.dumps({'archive_sha256':'not-a-digest'}))
            with self.assertRaises(r.BuildFailure):r.pinned_sdk_sha(source,'not-a-digest')

    def test_linux_native_gui_harness_has_cage_without_x11_test_server(self):
        workflow=(Path(__file__).parent/'.github/workflows/headspace-release.yml').read_text()
        command=next(line for line in workflow.splitlines() if 'sudo apt-get install ' in line)
        packages=set(command.split())
        self.assertTrue({'cage','mesa-vulkan-drivers'} <= packages)
        self.assertFalse({'weston','xvfb','xserver-xorg-video-dummy'} & packages)

    def test_phase_progress_is_flushed_and_cannot_emit_arbitrary_data(self):
        target='aarch64-unknown-linux-gnu'
        with patch('builtins.print') as emit:
            r.phase_progress(target,'cargo_test','running')
            args,kwargs=emit.call_args
            self.assertEqual(json.loads(args[0]),dict(target=target,phase='cargo_test',status='running'))
            self.assertEqual(kwargs,dict(flush=True))
        for values in [(target,'/private/source','running'),(target,'cargo_build','PRIVATE'),('private-target','audit','passed')]:
            with self.subTest(values=values),patch('builtins.print') as emit:
                with self.assertRaises(r.BuildFailure):r.phase_progress(*values)
                emit.assert_not_called()

    def test_product_checks_exclude_legacy_reference_and_build_actual_release_frontend(self):
        rust=['rustup','run','1.98.1','rustc'];target='aarch64-pc-windows-msvc'
        tests=r.product_cargo_command(rust,target,'test');build=r.product_cargo_command(rust,target,'build')
        self.assertIn('--no-fail-fast',tests)
        self.assertNotIn('--no-fail-fast',build)
        self.assertNotIn('--workspace',tests)
        self.assertNotIn('headspace-app',tests)
        self.assertEqual([tests[i+1]for i,v in enumerate(tests)if v=='-p'],['headspace-core','headspace-ai','headspace-mcp','headspace-gpui'])
        self.assertEqual([build[i+1]for i,v in enumerate(build)if v=='-p'],['headspace-gpui','headspace-mcp'])
        self.assertIn('--release',build)
        self.assertIn('--locked',tests)

    def test_release_semver_matches_immutable_source_not_ci_run_number(self):
        for value in ['0.1.0-alpha.1','1.2.3','1.2.3+build.77']:
            self.assertEqual(r.validate_version(value),value)
        for value in ['v0.1.0','0.1.01','1.0.0-alpha.01','1.2.3;echo','1.2٣.0']:
            with self.assertRaises(r.BuildFailure):r.validate_version(value)
        with tempfile.TemporaryDirectory()as directory:
            source=Path(directory);(source/'Cargo.toml').write_text('[workspace.package]\nversion="0.1.0-alpha.1"\n')
            self.assertEqual(r.source_version(source,'0.1.0-alpha.1'),'0.1.0-alpha.1')
            with self.assertRaises(r.BuildFailure):r.source_version(source,'0.1.77')

    def test_sdk_diagnostics_forward_only_allowlisted_coordinates_and_codes(self):
        report={'phase':'compile','exit_code':2,'private':'DO NOT EXPOSE','diagnostics':[
            {'file':'src/bloom.c','line':42,'code':'C2065','message':'SECRET symbol source text'},
            {'file':'/private/absolute.c','line':7,'code':'C9999','message':'PRIVATE'},
            {'file':'src/bloom.c','line':-1,'code':'SECRET'},
            {'file':'../escape.c','line':10,'code':'raw source'},
            {'code':'LNK2019','message':'PRIVATE external symbol'}]}
        sanitized=r.safe_sdk_report('private raw output\n'+json.dumps(report),{'src/bloom.c'})
        self.assertEqual(sanitized,dict(phase='compile',exit_code=2,diagnostics=[dict(file='src/bloom.c',line=42,code='C2065'),dict(code='C9999'),dict(code='LNK2019')]))
        self.assertNotIn('SECRET',json.dumps(sanitized));self.assertNotIn('private',json.dumps(sanitized))
        self.assertIsNone(r.safe_sdk_report('raw compiler source',set()))
        self.assertIsNone(r.safe_sdk_report(json.dumps({'phase':'arbitrary private payload','exit_code':1,'diagnostics':[]}),set()))

    def test_actual_driver_failure_preserves_only_pinned_safe_json(self):
        with tempfile.TemporaryDirectory()as directory:
            source=Path(directory);manifest=source/'docs/release/bloom-sdk-input.json';manifest.parent.mkdir(parents=True)
            manifest.write_text(json.dumps({'diagnostic_files':['src/bloom.c']}))
            report=dict(phase='compile',exit_code=2,diagnostics=[dict(file='src/bloom.c',line=17,code='C2065',message='PRIVATE source')])
            code='import sys;print('+repr(json.dumps(report))+');print("PRIVATE compiler source",file=sys.stderr);raise SystemExit(2)'
            with self.assertRaises(r.SdkFailure)as error:r.run_sdk([sys.executable,'-c',code],source,{},timeout=5)
            self.assertEqual(error.exception.report,dict(phase='compile',exit_code=2,diagnostics=[dict(file='src/bloom.c',line=17,code='C2065')]))
            self.assertNotIn('PRIVATE',str(error.exception))
            manifest.write_text(json.dumps({'diagnostic_files':['../escape.c']}))
            with self.assertRaises(r.SdkFailure)as error:r.run_sdk([sys.executable,'-c','raise SystemExit(0)'],source,{},timeout=5)
            self.assertEqual(error.exception.code,'sdk_diagnostic_contract')

    def test_cargo_diagnostics_strip_rendered_messages_private_paths_and_symbols(self):
        def item(file):return dict(reason='compiler-message',message=dict(level='error',code={'code':'E0432'},message='PRIVATE source symbol',rendered='PRIVATE source snippet',spans=[dict(file_name=file,line_start=77,is_primary=True)]))
        output='\n'.join(json.dumps(item(file))for file in ['crates/headspace-core/src/lib.rs','.private/bloomdb/bindings/rust/src/lib.rs','/home/PRIVATE/other.rs'])
        output+='\nerror: the lock file PRIVATE needs to be updated but --locked was passed'
        report=r.safe_cargo_report(output,{'crates/headspace-core/src/lib.rs'},{'bindings/rust/src/lib.rs'})
        self.assertEqual(report['diagnostics'],[dict(file='crates/headspace-core/src/lib.rs',line=77,code='E0432'),dict(file='sdk/bindings/rust/src/lib.rs',line=77,code='E0432'),dict(code='E0432')])
        self.assertEqual(report['classifications'],['locked_dependency_update_required'])
        self.assertNotIn('PRIVATE',json.dumps(report));self.assertNotIn('symbol',json.dumps(report))

    def test_actual_non_json_failure_categories_are_constant_no_payload(self):
        for text,category in [('failed to parse manifest PRIVATE','manifest_parse_failed'),('rustc 1.0 is not supported by the following packages PRIVATE','rust_toolchain_incompatible'),('error: linking with PRIVATE failed','linker_invocation_failed'),('linker PRIVATE not found','linker_unavailable'),('Access is denied PRIVATE','filesystem_access_denied'),('No space left on device PRIVATE','filesystem_full'),('test result: FAILED PRIVATE','test_binary_failed')]:
            report=r.safe_cargo_report(text,set(),set())
            self.assertIn(category,report['classifications']);self.assertNotIn('PRIVATE',json.dumps(report))

    def test_failed_subprocess_encrypts_raw_log_and_scrubs_key_from_child(self):
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        identity=dict(source_input_sha256='a'*64,recipe_revision='b'*40,app_source_revision='c'*40,target='aarch64-unknown-linux-gnu',version='0.1.0-alpha.1',sdk_version='0.1.0-alpha.1',run_id=123,worker_sha='d'*40,phase='cargo_test')
        with tempfile.TemporaryDirectory()as directory:
            source=Path(directory)/'source';docs=source/'docs/release';docs.mkdir(parents=True);(docs/'bloom-sdk-input.json').write_text(json.dumps(dict(diagnostic_files=[])))
            output=Path(directory)/'public'
            key=base64.b64encode(b'k'*32).decode()
            code='import os;print("key_present="+str("BLOOM_ARTIFACT_KEY" in os.environ));print("PRIVATE source payload");raise SystemExit(1)'
            with patch.dict(r.os.environ,{'BLOOM_ARTIFACT_KEY':key}),self.assertRaises(r.CargoFailure)as error:
                r.run_cargo([sys.executable,'-c',code],'cargo_test',source,dict(BLOOM_ARTIFACT_KEY=key,GITHUB_TOKEN='PRIVATE-token'),timeout=5,failure_output=output,failure_identity=identity)
            receipt=error.exception.encrypted_log;self.assertEqual(receipt['status'],'encrypted')
            encrypted=(output/receipt['ciphertext']).read_bytes();metadata=(output/receipt['manifest']).read_bytes()
            raw=AESGCM(b'k'*32).decrypt(encrypted[:12],encrypted[12:],metadata)
            self.assertIn(b'key_present=False',raw);self.assertIn(b'PRIVATE source payload',raw)
            self.assertNotIn(b'PRIVATE',encrypted);self.assertNotIn(b'PRIVATE',metadata)
            self.assertEqual({p.suffix for p in output.iterdir()},{'.aesgcm','.json'})

    def test_sdk_chunks_are_bounded_and_counted(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'sdk'
            r.append_sdk(path,1,'YWJj',2);r.append_sdk(path,2,'ZA==',2)
            self.assertEqual(path.read_text(),'YWJjZA==')
            r.append_sdk(path,3,'',2)
            for index,chunk,count in [(1,'',2),(1,'a'*12289,2),(3,'YWJj',2),(25,'',24)]:
                with self.assertRaises(r.BuildFailure):r.append_sdk(path,index,chunk,count)
        for value in ['0','25','1;echo bad',None]:
            with self.assertRaises(r.BuildFailure):r.sdk_count(value)

    def test_extract_exact_checksum_contained_regular_files(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);payload=self.archive([('bloomdb/src/a.c',tarfile.REGTYPE,b'fixture')]);encoded=root/'sdk.b64';encoded.write_bytes(base64.b64encode(payload))
            target=r.extract_sdk(encoded,hashlib.sha256(payload).hexdigest(),root/'out')
            self.assertEqual((target/'src/a.c').read_bytes(),b'fixture')
            with self.assertRaises(r.BuildFailure):r.extract_sdk(encoded,'a'*64,root/'bad')

    def test_archive_links_escapes_duplicates_and_wrong_prefix_rejected(self):
        for entries in [[('bloomdb/a',tarfile.SYMTYPE,b'')],[('bloomdb/../outside',tarfile.REGTYPE,b'')],[('/absolute',tarfile.REGTYPE,b'')],[('other/a',tarfile.REGTYPE,b'')],[('bloomdb/a',tarfile.REGTYPE,b'a'),('bloomdb/a',tarfile.REGTYPE,b'b')],[('bloomdb/C:bad',tarfile.REGTYPE,b'')]]:
            with self.subTest(entries=entries),tempfile.TemporaryDirectory()as directory:
                root=Path(directory);payload=self.archive(entries);encoded=root/'sdk';encoded.write_bytes(base64.b64encode(payload))
                with self.assertRaises(r.BuildFailure):r.extract_sdk(encoded,hashlib.sha256(payload).hexdigest(),root/'out')

    def test_artifact_inventory_requires_every_real_format_and_matching_hash(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);target='aarch64-unknown-linux-gnu';revision='a'*40;files=[]
            for fmt in ['deb','rpm']:
                path=root/('headspace-0.1.0-'+target+'.'+fmt);path.write_bytes(fmt.encode());files.append(dict(path=path.name,format=fmt,sha256=hashlib.sha256(fmt.encode()).hexdigest()))
            doc=dict(target=target,source_revision=revision,version='0.1.0',files=files)
            inventory=root/('inventory-'+target+'.json');inventory.write_text(json.dumps(doc));r.artifact_receipt(root,target,revision)
            (root/files[0]['path']).write_bytes(b'changed')
            with self.assertRaises(r.BuildFailure):r.artifact_receipt(root,target,revision)
            doc['files']=files[1:];inventory.write_text(json.dumps(doc))
            with self.assertRaises(r.BuildFailure):r.artifact_receipt(root,target,revision)


if __name__=='__main__':unittest.main()
