"""No network, real keys or private SDK contents: encrypted pipeline boundaries."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parent/'scripts'))
import sdk_artifacts as sdk
import sdk_consumer as consumer

VERSION='0.1.0-alpha.1'
SOURCE='a'*64
PRODUCER=dict(repository=consumer.REPOSITORY,workflow='bloom-sdk.yml',run_id=123,head_sha='b'*40,recipe_revision='c'*40)


class SDKArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.key=patch.dict(os.environ,{'BLOOM_ARTIFACT_KEY':base64.b64encode(bytes(range(32))).decode()});self.key.start();self.addCleanup(self.key.stop)

    def fixture(self,target='aarch64-unknown-linux-gnu'):
        system='Windows'if'windows'in target else'Darwin'if'apple'in target else'Linux'
        arch='aarch64'if target.startswith('aarch64')else'x86_64'
        files={name:('controlled '+name).encode()for name in sdk.FIXED_FILES}
        files['lib/bloom.lib'if system=='Windows'else'lib/libbloom.a']=b'controlled native archive'
        if system=='Darwin':files['lib/libcrypto.a']=b'exact controlled static crypto archive'
        identity=dict(sdk_version=VERSION,source_input_sha256=SOURCE,target=target,producer=PRODUCER,private_source_revision='d'*40,private_source_subdirectory='sdk/headspace/input/bloomdb',abi=dict(os=system,arch=arch,pointer_width=64,endianness='little'))
        return files,identity

    def lock(self):
        return dict(schema_version=1,sdk_version=VERSION,source_input_sha256=SOURCE,producer=PRODUCER,targets={target:dict(artifact_name='bloom-sdk-'+VERSION+'-'+target,ciphertext_sha256='e'*64,manifest_sha256='f'*64)for target in consumer.TARGETS})

    def test_authenticated_roundtrip_for_every_native_target_is_relocatable(self):
        for target in consumer.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory()as directory:
                files,identity=self.fixture(target);encrypted,metadata=sdk.make_envelope(files,identity)
                self.assertNotIn(b'controlled native archive',encrypted)
                root=Path(directory)/'sdk';manifest=sdk.unpack_envelope(encrypted,metadata,root,target,VERSION,SOURCE)
                self.assertEqual(manifest['tests'],dict(native_build='passed',required_sdk_semantics='passed'))
                for name,data in files.items():self.assertEqual((root/name).read_bytes(),data)
                self.assertFalse((root/'src').exists())
                env=sdk.sdk_link_env(root,target);self.assertEqual(Path(env['BLOOM_LIB_DIR']).resolve(),(root/'lib').resolve())
                self.assertNotIn('/producer/',json.dumps(env))
                self.assertTrue(env['BLOOM_EXTRA_LIB_DIRS']);self.assertTrue(all(env['BLOOM_EXTRA_LIB_DIRS'].split(os.pathsep)))
                self.assertEqual(env['BLOOM_STATIC_LIBS'],'bcrypt'if'windows'in target else'static=crypto,m,pthread'if'apple'in target else'crypto,m,pthread')

    def test_ciphertext_metadata_key_and_test_identity_tamper_fail_closed(self):
        files,identity=self.fixture();encrypted,metadata=sdk.make_envelope(files,identity)
        with tempfile.TemporaryDirectory()as directory:
            bad=encrypted[:-1]+bytes([encrypted[-1]^1])
            with self.assertRaises(sdk.ArtifactError):sdk.unpack_envelope(bad,metadata,Path(directory)/'bad','aarch64-unknown-linux-gnu',VERSION,SOURCE)
            with patch.dict(os.environ,{'BLOOM_ARTIFACT_KEY':base64.b64encode(b'x'*32).decode()}),self.assertRaises(sdk.ArtifactError):sdk.unpack_envelope(encrypted,metadata,Path(directory)/'key','aarch64-unknown-linux-gnu',VERSION,SOURCE)
            with self.assertRaises(sdk.ArtifactError):sdk.unpack_envelope(encrypted,metadata,Path(directory)/'version','aarch64-unknown-linux-gnu','0.2.0',SOURCE)
            doc=json.loads(metadata);doc['tests']['required_sdk_semantics']='not_run'
            with self.assertRaises(sdk.ArtifactError):sdk.validate_manifest(doc,'aarch64-unknown-linux-gnu',VERSION,SOURCE)

    def test_engine_source_and_wrong_abi_cannot_enter_even_encrypted_sdk(self):
        files,identity=self.fixture();files['src/private_engine.c']=b'forbidden source'
        with self.assertRaises(sdk.ArtifactError):sdk.make_envelope(files,identity)
        files,identity=self.fixture();identity['abi']['arch']='x86_64'
        with self.assertRaises(sdk.ArtifactError):sdk.make_envelope(files,identity)
        files,identity=self.fixture('aarch64-apple-darwin');files.pop('lib/libcrypto.a')
        with self.assertRaises(sdk.ArtifactError):sdk.make_envelope(files,identity)

    def test_authenticated_archive_path_and_link_injection_rejected_before_write(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import gzip
        files,identity=self.fixture();_,metadata=sdk.make_envelope(files,identity)
        for kind,name in [(tarfile.REGTYPE,'../outside'),(tarfile.SYMTYPE,'lib/libbloom.a')]:
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w')as archive:
                item=tarfile.TarInfo(name);item.type=kind;item.linkname='/outside';archive.addfile(item)
            nonce=b'n'*12;encrypted=nonce+AESGCM(sdk.secret_key()).encrypt(nonce,gzip.compress(stream.getvalue()),metadata)
            with tempfile.TemporaryDirectory()as directory,self.assertRaises(sdk.ArtifactError):sdk.unpack_envelope(encrypted,metadata,Path(directory)/'sdk','aarch64-unknown-linux-gnu',VERSION,SOURCE)

    def test_failure_log_envelope_authenticates_context_without_plaintext_leak(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        identity=dict(source_input_sha256=SOURCE,recipe_revision='c'*40,app_source_revision='e'*40,target='aarch64-unknown-linux-gnu',version=VERSION,sdk_version=VERSION,run_id=123,worker_sha='b'*40,phase='cargo_test')
        raw=b'PRIVATE compiler source and absolute host paths'
        encrypted,metadata=sdk.encrypt_failure_log(raw,identity)
        self.assertNotIn(raw,encrypted);self.assertNotIn(b'PRIVATE',metadata)
        self.assertEqual(AESGCM(sdk.secret_key()).decrypt(encrypted[:12],encrypted[12:],metadata),raw)
        with self.assertRaises(Exception):AESGCM(sdk.secret_key()).decrypt(encrypted[:12],encrypted[12:],metadata+b' ')
        with self.assertRaises(sdk.ArtifactError):sdk.encrypt_failure_log(raw,dict(identity,worker_sha='invalid'))
        data=b'x'*(sdk.MAX_FAILURE_LOG+8);encrypted,metadata=sdk.encrypt_failure_log(data,identity)
        self.assertTrue(json.loads(metadata)['truncated']);self.assertEqual(len(AESGCM(sdk.secret_key()).decrypt(encrypted[:12],encrypted[12:],metadata)),sdk.MAX_FAILURE_LOG)

    def test_consumer_requires_private_revision_and_rejects_symlink_ancestor(self):
        with tempfile.TemporaryDirectory()as directory:
            source=Path(directory)/'source';docs=source/'docs/release';docs.mkdir(parents=True)
            pin=dict(sdk_version=VERSION,archive_sha256=SOURCE)
            (docs/'bloom-sdk-input.json').write_text(json.dumps(pin));(docs/'bloom-sdk-lock.json').write_text(json.dumps(self.lock()))
            with self.assertRaises(sdk.ArtifactError):consumer.read_lock(source)
            pin['private_source_revision']='d'*40;(docs/'bloom-sdk-input.json').write_text(json.dumps(pin))
            target='aarch64-unknown-linux-gnu';files,identity=self.fixture(target);encrypted,metadata=sdk.make_envelope(files,identity)
            lock=self.lock();lock['targets'][target].update(ciphertext_sha256=hashlib.sha256(encrypted).hexdigest(),manifest_sha256=hashlib.sha256(metadata).hexdigest());(docs/'bloom-sdk-lock.json').write_text(json.dumps(lock))
            outside=Path(directory)/'outside';outside.mkdir()
            try:(source/'.private').symlink_to(outside,target_is_directory=True)
            except OSError:self.skipTest('Native symlinks unavailable')
            with self.assertRaises(sdk.ArtifactError):consumer.consume(source,target,lambda url,limit:metadata if url.endswith('.manifest.json')else encrypted)
            self.assertEqual(list(outside.iterdir()),[])

    def test_consumer_requires_complete_source_lock_and_uses_no_engine_input(self):
        with tempfile.TemporaryDirectory()as directory:
            source=Path(directory);docs=source/'docs/release';docs.mkdir(parents=True)
            (docs/'bloom-sdk-input.json').write_text(json.dumps(dict(sdk_version=VERSION,archive_sha256=SOURCE,private_source_revision='d'*40,private_source_subdirectory='sdk/headspace/input/bloomdb')))
            target='aarch64-unknown-linux-gnu';files,identity=self.fixture(target);encrypted,metadata=sdk.make_envelope(files,identity)
            lock=self.lock();lock['targets'][target].update(ciphertext_sha256=hashlib.sha256(encrypted).hexdigest(),manifest_sha256=hashlib.sha256(metadata).hexdigest())
            path=docs/'bloom-sdk-lock.json';path.write_text(json.dumps(lock))
            urls=[]
            def download(url,maximum):
                urls.append(url);return metadata if url.endswith('.manifest.json')else encrypted
            env,receipt=consumer.consume(source,target,download)
            self.assertFalse(receipt['engine_recompiled']);self.assertFalse((source/'.private/bloomdb/src').exists());self.assertTrue((source/'.private/bloomdb/bindings/rust/Cargo.toml').is_file())
            self.assertTrue(all(u.startswith(consumer.BASE+VERSION+'/')for u in urls));self.assertIn('BLOOM_LIB_DIR',env)
            lock['targets'].pop('x86_64-pc-windows-msvc');path.write_text(json.dumps(lock))
            with self.assertRaises(sdk.ArtifactError):consumer.read_lock(source)


if __name__=='__main__':unittest.main()
