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

    def test_product_checks_exclude_legacy_reference_and_build_actual_release_frontend(self):
        rust=['rustup','run','1.98.1','rustc'];target='aarch64-pc-windows-msvc'
        tests=r.product_cargo_command(rust,target,'test');build=r.product_cargo_command(rust,target,'build')
        self.assertNotIn('--workspace',tests)
        self.assertNotIn('headspace-app',tests)
        self.assertEqual([tests[i+1]for i,v in enumerate(tests)if v=='-p'],['headspace-core','headspace-ai','headspace-mcp','headspace-gpui'])
        self.assertEqual([build[i+1]for i,v in enumerate(build)if v=='-p'],['headspace-gpui','headspace-mcp'])
        self.assertIn('--release',build)
        self.assertIn('--locked',tests)

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
