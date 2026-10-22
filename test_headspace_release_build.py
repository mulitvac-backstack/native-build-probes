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

    def test_alpha4_native_admission_requires_no_project_live_mcp_receipt(self):
        live=dict(status='passed',mode='stdio_no_project',initialize=True,tools_discovered=True,live_bloom_workspace=True,unsaved_text=True,
            current_selection=True,original_png_bytes=True,snapshot_guarded=True,loopback_connections=1,external_network_requests=0)
        for historical in ('0.1.0-alpha.1','0.1.0-alpha.2','0.1.0-alpha.3'):
            self.assertTrue(r.live_mcp_proof({},historical))
        for version in ('0.1.0-alpha.4','0.1.0-alpha.5','0.2.0'):
            self.assertTrue(r.requires_live_mcp(version))
            self.assertFalse(r.live_mcp_proof({},version))
            self.assertTrue(r.live_mcp_proof(dict(live_mcp=live,external_network_requests=0),version))
        self.assertFalse(r.live_mcp_proof({},'0.1.0-alpha.4'))
        self.assertTrue(r.live_mcp_proof(dict(live_mcp=live,external_network_requests=0),'0.1.0-alpha.4'))
        for key,value in [('status','blocked'),('mode','saved_project'),('initialize',1),('unsaved_text',False),
                          ('current_selection',None),('original_png_bytes',False),('tools_discovered',False),
                              ('live_bloom_workspace',False),('snapshot_guarded',False),('loopback_connections',True),('external_network_requests',False)]:
            self.assertFalse(r.live_mcp_proof(dict(live_mcp=dict(live,**{key:value}),external_network_requests=0),'0.1.0-alpha.4'))
            missing=dict(live);missing.pop(key)
            self.assertFalse(r.live_mcp_proof(dict(live_mcp=missing,external_network_requests=0),'0.1.0-alpha.4'))
        for count in (None,False,1):
            self.assertFalse(r.live_mcp_proof(dict(live_mcp=live,external_network_requests=count),'0.1.0-alpha.4'))

    def test_linux_native_gui_harness_has_cage_without_x11_test_server(self):
        workflow=(Path(__file__).parent/'.github/workflows/headspace-release.yml').read_text()
        command=next(line for line in workflow.splitlines() if 'sudo apt-get install ' in line)
        packages=set(command.split())
        self.assertTrue({'cage','mesa-vulkan-drivers'} <= packages)
        self.assertFalse({'weston','xvfb','xserver-xorg-video-dummy'} & packages)

    def test_checkpoint_metrics_are_exact_bounded_data_not_log_text(self):
        valid=dict(operation='save',duration_us=123456,success=True)
        def line(item):return b'HEADSPACE_CHECKPOINT_METRIC '+json.dumps(item).encode()+b'\n'
        invalid=[dict(valid,duration_us=True),dict(valid,duration_us=-1),dict(valid,duration_us=2_400_000_001),
                 dict(valid,duration_us='42'),dict(valid,success=1),dict(valid,operation='PRIVATE'),dict(valid,path='/PRIVATE')]
        lines=[b'PRIVATE raw source text\n',b'prefix '+line(valid),b'HEADSPACE_CHECKPOINT_METRIC invalid',
               b'HEADSPACE_CHECKPOINT_METRIC {"operation":"save","operation":"camera","duration_us":1,"success":true}']
        lines += [line(item)for item in invalid]+[line(valid)]*101
        report=r.checkpoint_metrics(lines)
        self.assertEqual(report,dict(events=[valid]*100,omitted_count=1))
        self.assertNotIn('PRIVATE',json.dumps(report))
        self.assertEqual(r.checkpoint_metrics([b'HEADSPACE_CHECKPOINT_METRIC '+b' '*600]),dict(events=[],omitted_count=0))

    def test_successful_cargo_returns_only_checkpoint_metrics_and_strips_secrets(self):
        with tempfile.TemporaryDirectory()as directory:
            source=Path(directory);pin=source/'docs/release/bloom-sdk-input.json';pin.parent.mkdir(parents=True);pin.write_text('{"diagnostic_files":[]}')
            metric=dict(operation='camera',duration_us=42,success=True)
            code='import os,sys;assert "BLOOM_ARTIFACT_KEY" not in os.environ;print("PRIVATE raw body");sys.stderr.write('+repr('\nHEADSPACE_CHECKPOINT_METRIC '+json.dumps(metric)+'\n')+')'
            with patch('builtins.print')as emit:
                report=r.run_cargo([sys.executable,'-c',code],'cargo_test',source,dict(BLOOM_ARTIFACT_KEY='PRIVATE'),timeout=5)
                emit.assert_not_called()
            self.assertEqual(report,dict(events=[metric],omitted_count=0))

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
        self.assertEqual([build[i+1]for i,v in enumerate(build)if v=='-p'],['headspace-gpui'])
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

    def test_artifact_inventory_requires_one_native_executable_not_installer_collection(self):
        for target in ['aarch64-unknown-linux-gnu','x86_64-apple-darwin','aarch64-pc-windows-msvc']:
            with self.subTest(target=target),tempfile.TemporaryDirectory()as directory:
                root=Path(directory);revision='a'*40;name='headspace-0.1.0-'+target+('.exe'if'windows'in target else'')
                path=root/name;path.write_bytes(b'controlled-native-fixture')
                entry=dict(path=name,format='binary',bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                doc=dict(schema_version=2,delivery='single_native_executable',target=target,source_revision=revision,version='0.1.0',files=[entry])
                inventory=root/('inventory-'+target+'.json');inventory.write_text(json.dumps(doc));r.artifact_receipt(root,target,revision)
                path.write_bytes(b'changed')
                with self.assertRaises(r.BuildFailure):r.artifact_receipt(root,target,revision)
                path.write_bytes(b'controlled-native-fixture');doc['files']=[entry,dict(entry)];inventory.write_text(json.dumps(doc))
                with self.assertRaises(r.BuildFailure):r.artifact_receipt(root,target,revision)
                doc['files']=[dict(entry,path=name+'.zip')];inventory.write_text(json.dumps(doc))
                with self.assertRaises(r.BuildFailure):r.artifact_receipt(root,target,revision)

    def test_workflow_has_only_raw_payload_glob_and_no_installer_compilers(self):
        workflow=(Path(__file__).parent/'.github/workflows/headspace-release.yml').read_text()
        self.assertEqual(set(r.FORMATS.values()),{('binary',)})
        self.assertIn('/headspace-dist/headspace-*',workflow)
        for old in ['wix --version','headspace-*.deb','headspace-*.rpm','headspace-*.dmg','headspace-*.msi','headspace-*.app.zip']:
            self.assertNotIn(old,workflow)


if __name__=='__main__':unittest.main()
