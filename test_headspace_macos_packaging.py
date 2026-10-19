"""Offline packaging boundaries; fixture bytes do not qualify native apps."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('mac_packaging', ROOT/'scripts/headspace_macos_packaging.py')
r = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(r)


class MacPackagingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.profile = dict(schema_version=1,owner_repository=r.OWNER,binary_source_revision=r.SOURCE,
                            binary_version=r.VERSION,input_run_id=r.RUN,input_worker_revision=r.WORKER,
                            input_repository=r.REPOSITORY,recipe_path='scripts/package-macos.py',
                            recipe_revision='a'*40,recipe_sha256='b'*64,targets={})
        for label,target in r.TARGETS.items():
            self.profile['targets'][label] = dict(target=target,artifact_name=f'headspace-{label}-{r.SOURCE}',executable_sha256='c'*64)

    def input(self, label):
        target=r.TARGETS[label];directory=self.root/label;directory.mkdir()
        cpu=0x1000007 if target.startswith('x86_64') else 0x100000c
        binary=directory/f'headspace-{r.VERSION}-{target}'
        binary.write_bytes(b'\xcf\xfa\xed\xfe'+cpu.to_bytes(4,'little')+b'controlled fixture')
        digest=r.sha(binary);self.profile['targets'][label]['executable_sha256']=digest
        inventory=dict(source_revision=r.SOURCE,target=target,version=r.VERSION,
                       files=[dict(path=binary.name,sha256=digest,bytes=binary.stat().st_size)])
        build=dict(source_revision=r.SOURCE,target=target,runner=label,status='passed',cargo_test='passed',cargo_build='passed')
        (directory/f'inventory-{target}.json').write_text(json.dumps(inventory))
        (directory/f'build-{target}.json').write_text(json.dumps(build))
        for mode in ('audit','native'):
            proof=dict(source_revision=r.SOURCE,target=target,runner=label,mode=mode,audit=dict(sha256=digest),
                       cli=dict(status='passed',embedded_notices=7,mcp=dict(status='passed',embedded_image_bytes=True)))
            if mode=='native':
                proof.update(status='passed_bounded_native_checks',native_gui=dict(status='passed',working_recovery=True,portable_roundtrip=True,
                    native_engine=dict(draw_total_ms=dict(count=3),platform_submit_ms=dict(count=3))))
            prefix='verify-native-'if mode=='native'else'verify-'
            (directory/f'{prefix}{target}-binary.json').write_text(json.dumps(proof))
        return directory,binary

    def test_profile_fixed_owner_original_run_and_two_targets(self):
        path=self.root/'profile.json';path.write_text(json.dumps(self.profile));self.assertEqual(r.load_profile(path),self.profile)
        for changes in [dict(input_run_id=1),dict(input_repository='other/repo'),dict(binary_source_revision='d'*40),dict(recipe_revision='main'),dict(owner_repository='https://other.invalid/repo')]:
            with self.subTest(changes=changes):
                path.write_text(json.dumps(dict(self.profile,**changes)))
                with self.assertRaises(r.BuildFailure):r.load_profile(path)

    def test_both_native_architecture_fixtures_require_exact_five_files_and_hash(self):
        for label in r.TARGETS:
            with self.subTest(label=label):
                directory,binary=self.input(label);self.assertEqual(r.validate_input(directory,self.profile,label),binary)
                (directory/'extra-private-file').write_bytes(b'extra')
                with self.assertRaises(r.BuildFailure):r.validate_input(directory,self.profile,label)
                (directory/'extra-private-file').unlink();binary.write_bytes(binary.read_bytes()+b'tamper')
                with self.assertRaises(r.BuildFailure):r.validate_input(directory,self.profile,label)

    def test_native_input_needs_draw_submission_and_recovery_not_green_build_alone(self):
        label='macos-15';directory,binary=self.input(label);target=r.TARGETS[label]
        path=directory/f'verify-native-{target}-binary.json';original=json.loads(path.read_text())
        for key,value in [('working_recovery',False),('portable_roundtrip',False),('status','blocked'),('native_engine',dict(draw_total_ms=dict(count=3),platform_submit_ms=dict(count=0)))]:
            proof=copy.deepcopy(original);proof['native_gui'][key]=value;path.write_text(json.dumps(proof))
            with self.subTest(key=key),self.assertRaises(r.BuildFailure):r.validate_input(directory,self.profile,label)

    def test_owner_recipe_cannot_inherit_download_or_provider_credentials(self):
        original=dict(PATH='/bin',GH_TOKEN='private',GITHUB_TOKEN='private',ACTIONS_RUNTIME_TOKEN='private',BLOOM_ARTIFACT_KEY='private',OPENAI_API_KEY='private',AWS_SECRET_ACCESS_KEY='private')
        self.assertEqual(r.recipe_environment(original),dict(PATH='/bin'))

    def test_failed_recipe_reports_only_allowlisted_tool_and_source_location(self):
        private='PRIVATE_SECRET_PATH_AND_MESSAGE'
        body=f'File "/{private}/scripts/package-macos.py", line 166, in seal_app\nRuntimeError: codesign exited 1\n{private}\n'
        self.assertEqual(r.safe_recipe_diagnostic(body),dict(file='package-macos.py',line=166,function='seal_app',code='native_tool_failed',tool='codesign',exit_code=1))
        self.assertNotIn(private,json.dumps(r.safe_recipe_diagnostic(body)))
        script='import sys;sys.stderr.write('+repr(body)+');sys.exit(1)'
        with self.assertRaises(r.BuildFailure)as caught:
            r.run_recipe([sys.executable,'-c',script],self.root,{})
        self.assertEqual(caught.exception.recipe_diagnostic['tool'],'codesign')
        self.assertNotIn(private,str(caught.exception))

    def test_output_allows_only_one_hashed_dmg_and_bounded_inventory(self):
        label='macos-15';target=r.TARGETS[label];candidate=self.root/'out';candidate.mkdir()
        dmg=candidate/f'headspace-{r.VERSION}-pkg1-{target}.dmg';dmg.write_bytes(b'controlled disk-image fixture')
        native=dict.fromkeys(('dmg_integrity','read_only_mount','application_bundle_layout','clean_copy_install','version','removal'),'passed')
        native.update(embedded_notices=7,synthetic_user_data_preserved=True,mcp=dict(status='passed',embedded_image_bytes=True),
            native_gui=dict(native_gui=dict(status='passed',working_recovery=True,portable_roundtrip=True,native_engine=dict(draw_total_ms=dict(count=3),platform_submit_ms=dict(count=3)))))
        entry=dict(path=dmg.name,format='dmg',bytes=dmg.stat().st_size,sha256=r.sha(dmg),
            input_executable_sha256=self.profile['targets'][label]['executable_sha256'],packaged_executable_sha256='d'*64,
            bundle=dict(files={'Contents/MacOS/headspace':dict(sha256='d'*64)}),normalized_code_sha256='e'*64,
            normalized_code_identity=dict(status='passed',method='codesign_adhoc_resign_then_remove_signature_private_copies',
                canonical_identifier='io.backstack.Headspace.normalized',input_unsigned_sha256='e'*64,packaged_unsigned_sha256='e'*64),
            signing=dict(kind='ad_hoc',bundle_seal_verified=True,developer_id=False,notarized=False),native_verification=native)
        inventory=dict(schema_version=1,owner_repository=r.OWNER,source_revision=r.SOURCE,target=target,version=r.VERSION,package_revision=1,
            recipe_revision=self.profile['recipe_revision'],recipe_sha256=self.profile['recipe_sha256'],native_runner=label,
            original_release_assets_unchanged=True,status='passed_native_macos_package_checks',files=[entry])
        path=candidate/f'macos-package-inventory-{target}-r1.json';path.write_text(json.dumps(inventory))
        self.assertEqual(len(r.qualified_outputs(candidate,self.profile,label)[1]),2)
        for kind in ('normalized_identity','mcp','draw'):
            wrong=copy.deepcopy(inventory);item=wrong['files'][0]
            if kind=='normalized_identity':item['normalized_code_identity']['packaged_unsigned_sha256']='f'*64
            elif kind=='mcp':item['native_verification']['mcp']['embedded_image_bytes']=False
            else:item['native_verification']['native_gui']['native_gui']['native_engine']['platform_submit_ms']['count']=0
            path.write_text(json.dumps(wrong))
            with self.subTest(kind=kind),self.assertRaises(r.BuildFailure):r.qualified_outputs(candidate,self.profile,label)
        path.write_text(json.dumps(inventory))
        (candidate/'headspace-raw').write_bytes(b'no raw executable forwarding')
        with self.assertRaises(r.BuildFailure):r.qualified_outputs(candidate,self.profile,label)
        (candidate/'headspace-raw').unlink();dmg.write_bytes(b'tamper')
        with self.assertRaises(r.BuildFailure):r.qualified_outputs(candidate,self.profile,label)

    def test_workflow_has_only_two_standard_mac_jobs_no_compilers_or_secrets(self):
        workflow=(ROOT/'.github/workflows/headspace-macos-packaging.yml').read_text()
        self.assertIn('runner: [macos-15-intel, macos-15]',workflow)
        self.assertIn('actions: read',workflow)
        self.assertIn('GH_TOKEN: ${{ github.token }}',workflow)
        for prohibited in ('cargo ', 'rustup ', 'brew ', 'secrets.', 'windows-', 'ubuntu-', 'workflow_call', 'source_revision:'):
            self.assertNotIn(prohibited,workflow)
        self.assertNotIn('headspace-*',workflow)


if __name__=='__main__': unittest.main()
