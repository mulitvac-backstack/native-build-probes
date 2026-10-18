"""Independent Bloom source authority, archive and private compiler boundaries."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent / 'scripts'))
import bloom_profile as profile
import bloom_native as native
import bloom_sdk_build as producer
from sdk_artifacts import ArtifactError


class BloomProfileTests(unittest.TestCase):
    def fixture(self):
        files = {name: ('controlled ' + name).encode() for name in profile.FIXED_FILES - {'source-inventory.json'}}
        files['input/bloomdb/include/bloom.h'] = b'controlled private API fixture'
        files['sdk-profile.json'] = json.dumps(dict(sdk_version='0.1.0-alpha.2', binding_package_version='0.1.0', capability_profile='headspace-embedded-sdk-v1')).encode()
        files['source-inventory.json'] = json.dumps(dict(schema_version=1, files=[dict(path=name, size=len(data), sha256=profile.digest(data)) for name, data in sorted(files.items())])).encode()
        archive = self.archive(files)
        pin = dict(schema_version=2, source=dict(repository=profile.REPOSITORY, revision='a' * 40, subdirectory='sdk/embedded'),
                   sdk_version='0.1.0-alpha.2', binding_package_version='0.1.0', capability_profile='headspace-embedded-sdk-v1',
                   archive_sha256=profile.digest(archive), profile_sha256=profile.digest(files['sdk-profile.json']), inventory_sha256=profile.digest(files['source-inventory.json']))
        return files, archive, pin

    def archive(self, files, extra=None):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as tar:
            for name, data in files.items():
                item = tarfile.TarInfo('bloomdb-sdk/' + name)
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data))
            if extra is not None:
                tar.addfile(extra)
        return output.getvalue()

    def test_entire_bloom_owned_profile_is_pinned_before_writing(self):
        files, archive, pin = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            encoded = root / 'input'; encoded.write_bytes(base64.b64encode(archive))
            public_pin = root / 'pin.json'; public_pin.write_text(json.dumps(pin))
            checked = profile.read_pin(public_pin, 'a' * 40, '0.1.0-alpha.2', pin['archive_sha256'])
            extracted = profile.extract_profile(encoded, checked, root / 'extracted')
            self.assertEqual({p.relative_to(extracted).as_posix(): p.read_bytes() for p in extracted.rglob('*') if p.is_file()}, files)
            for source, version, sha in [('b' * 40, '0.1.0-alpha.2', pin['archive_sha256']), ('a' * 40, '0.1.0-alpha.1', pin['archive_sha256']), ('a' * 40, '0.1.0-alpha.2', 'f' * 64)]:
                with self.assertRaises(ArtifactError): profile.read_pin(public_pin, source, version, sha)
            pin['source']['repository'] = 'https://git.multivac.network/backstack.io/headspace'
            public_pin.write_text(json.dumps(pin))
            with self.assertRaises(ArtifactError): profile.read_pin(public_pin, 'a' * 40, '0.1.0-alpha.2', pin['archive_sha256'])

    def test_recipe_tamper_and_noninventoried_payload_are_rejected(self):
        files, _, pin = self.fixture()
        for name, data in [('recipe/build_bloom.py', b'changed'), ('input/bloomdb/extra.c', b'extra')]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                changed = dict(files); changed[name] = data
                archive = self.archive(changed); pin['archive_sha256'] = profile.digest(archive)
                root = Path(directory); encoded = root / 'input'; encoded.write_bytes(base64.b64encode(archive))
                with self.assertRaises(ArtifactError): profile.extract_profile(encoded, pin, root / 'output')
                self.assertFalse((root / 'output').exists())

    def test_links_duplicates_and_path_escape_cannot_enter_private_profile(self):
        files, _, pin = self.fixture()
        for name, kind in [('bloomdb-sdk/../outside', tarfile.REGTYPE), ('bloomdb-sdk/recipe/build_bloom.py', tarfile.REGTYPE), ('bloomdb-sdk/input/bloomdb/link', tarfile.SYMTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                item = tarfile.TarInfo(name); item.type = kind; item.linkname = '/outside'
                archive = self.archive(files, item); pin['archive_sha256'] = profile.digest(archive)
                root = Path(directory); encoded = root / 'input'; encoded.write_bytes(base64.b64encode(archive))
                with self.assertRaises(ArtifactError): profile.extract_profile(encoded, pin, root / 'output')
                self.assertFalse((root / 'output').exists())

    def test_malformed_compression_and_tar_are_constant_errors_before_writing(self):
        _, valid, pin = self.fixture()
        for bad in (b'PRIVATE not gzip', valid[:-5], gzip.compress(b'PRIVATE malformed tar')):
            with self.subTest(size=len(bad)), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); encoded = root / 'input'
                encoded.write_bytes(base64.b64encode(bad)); pin['archive_sha256'] = profile.digest(bad)
                with self.assertRaisesRegex(ArtifactError, '^Bloom profile archive encoding is invalid$'):
                    profile.extract_profile(encoded, pin, root / 'output')
                self.assertFalse((root / 'output').exists())

    def test_private_input_chunks_and_compiler_environment_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            profile.append_input(path, 1, 'YWJj', 2); profile.append_input(path, 2, 'ZA==', 2)
            self.assertEqual(base64.b64decode(path.read_bytes()), b'abcd')
            for values in [(3, 'extra', 2), (1, 'PRIVATE\n', 2), (1, 'x' * 12289, 2)]:
                with self.assertRaises(ArtifactError): profile.append_input(path, *values)
        self.assertEqual(profile.private_env(dict(PATH='allowed', BLOOM_INPUT_CHUNK='private', BLOOM_ARTIFACT_KEY='private', BLOOM_SDK_READ_TOKEN='private', GITHUB_TOKEN='private')), dict(PATH='allowed'))

    def test_driver_failure_retains_only_allowlisted_codes_and_encrypted_body(self):
        files, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source-inventory.json').write_bytes(files['source-inventory.json'])
            report = dict(phase='compile', exit_code=2, diagnostics=[dict(file='include/bloom.h', line=7, code='C2065', message='PRIVATE source'), dict(file='/PRIVATE/path', line=1, message='PRIVATE')])
            code = 'import os,json,sys;assert "BLOOM_ARTIFACT_KEY" not in os.environ;print(' + repr(json.dumps(report)) + ');print("PRIVATE raw body");sys.exit(2)'
            identity = dict(source_input_sha256='a' * 64, recipe_revision='b' * 40, app_source_revision='b' * 40, target='aarch64-unknown-linux-gnu', version='0.1.0-alpha.2', sdk_version='0.1.0-alpha.2', run_id=123, worker_sha='c' * 40, phase='sdk_build')
            key = base64.b64encode(bytes(range(32))).decode()
            with patch.dict(os.environ, {'BLOOM_ARTIFACT_KEY': key}), self.assertRaises(native.NativeFailure) as error:
                native.run_driver([sys.executable, '-c', code], root, root / 'sdk', dict(BLOOM_ARTIFACT_KEY=key), root / 'out', identity, timeout=5)
            self.assertEqual(error.exception.report, dict(phase='compile', exit_code=2, diagnostics=[dict(file='include/bloom.h', line=7, code='C2065')]))
            self.assertNotIn('PRIVATE', str(error.exception))
            self.assertEqual(error.exception.encrypted_log['status'], 'retained_encrypted')
            self.assertNotIn(b'PRIVATE', next((root / 'out').glob('*.aesgcm')).read_bytes())

    def test_bloom_producer_never_fetches_or_imports_headspace_recipe(self):
        root = Path(__file__).parent
        source = (root / 'scripts/bloom_sdk_build.py').read_text()
        self.assertNotIn('fetch_source', source)
        self.assertNotIn('headspace_release_build', source)
        self.assertNotIn('scripts/package.py', source)
        workflow = (root / '.github/workflows/bloom-sdk.yml').read_text()
        self.assertNotIn('scripts/headspace_release_build.py', workflow)
        self.assertIn('scripts/bloom_profile.py append-input', workflow)

    def test_standalone_producer_uses_only_the_bloom_owned_profile(self):
        files, _, pin = self.fixture()
        for name in ['include/bloom.h', 'bindings/rust/Cargo.toml', 'bindings/rust/build.rs', 'bindings/rust/src/lib.rs', 'headspace-capabilities.json']:
            files['input/bloomdb/' + name] = ('controlled ' + name).encode()
        files['recipe/build_bloom.py'] = b'''import argparse,json,os
from pathlib import Path
p=argparse.ArgumentParser()
for key in ['source','output','env-json','target']:p.add_argument('--'+key)
a=p.parse_args()
assert 'BLOOM_ARTIFACT_KEY' not in os.environ
o=Path(a.output);(o/'lib').mkdir(parents=True);(o/'build').mkdir()
(o/'lib/libbloom.a').write_bytes(b'controlled library fixture')
(o/'build/bloom-sdk-smoke').write_bytes(b'\\x7fELF\\x02\\x01'+bytes(12)+(183).to_bytes(2,'little')+bytes(64))
Path(a.env_json).write_text(json.dumps(dict(BLOOM_LIB_DIR=str(o/'lib'),BLOOM_STATIC='1',BLOOM_STATIC_LIBS='crypto,m,pthread',BLOOM_EXTRA_LIB_DIRS=str(o/'lib'))))
'''
        files['source-inventory.json'] = json.dumps(dict(schema_version=1, files=[dict(path=name, size=len(data), sha256=profile.digest(data)) for name, data in sorted(files.items()) if name != 'source-inventory.json'])).encode()
        archive = self.archive(files)
        pin.update(archive_sha256=profile.digest(archive), inventory_sha256=profile.digest(files['source-inventory.json']))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            encoded = root / 'input'; encoded.write_bytes(base64.b64encode(archive))
            public_pin = root / 'pin.json'; public_pin.write_text(json.dumps(pin))
            args = SimpleNamespace(runner='ubuntu-24.04-arm', revision='a' * 40, version='0.1.0-alpha.2', profile=public_pin, sdk_file=encoded, output=root / 'out')
            env = dict(GITHUB_RUN_ID='123', GITHUB_SHA='b' * 40, BLOOM_SDK_SHA256=pin['archive_sha256'], BLOOM_ARTIFACT_KEY=base64.b64encode(bytes(range(32))).decode())
            identity = dict(os='Linux', native_arch='aarch64', process_arch='aarch64', translated=False)
            with patch.dict(os.environ, env), patch.object(producer.probe, 'machine_identity', return_value=identity), patch('builtins.print'):
                self.assertEqual(producer.build(args), 0)
            receipt = json.loads((args.output / 'bloom-build-aarch64-unknown-linux-gnu.json').read_text())
            manifest = json.loads(next(args.output.glob('bloom-sdk-*.manifest.json')).read_text())
            self.assertEqual(receipt['producer'], manifest['producer'])
            self.assertEqual(receipt['producer']['recipe_repository'], 'backstack.io/bloomdb')
            self.assertEqual(receipt['producer']['recipe_revision'], 'a' * 40)
            self.assertEqual(receipt['private_source_subdirectory'], 'sdk/embedded/input/bloomdb')
            self.assertEqual(receipt['tests'], dict(native_build='passed', required_sdk_semantics='passed'))


if __name__ == '__main__': unittest.main()
