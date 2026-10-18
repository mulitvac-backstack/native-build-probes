"""Authenticated private SDK envelopes; public artifacts never contain plaintext.

cryptography is pinned by the native workflow. Engine C/build/log files are
always forbidden, even inside encrypted SDK archives.
"""
import base64
import gzip
import hashlib
import io
import json
import os
import re
from pathlib import Path, PurePosixPath
import tarfile

MAX_ARCHIVE=32*1024*1024
MAX_EXPANDED=80*1024*1024
FIXED_FILES={'include/bloom.h','bindings/rust/Cargo.toml','bindings/rust/build.rs','bindings/rust/src/lib.rs','capabilities.json','notices/BloomDB-NOTICE.txt','notices/cJSON-LICENSE.txt','notices/OpenSSL-LICENSE.txt'}
LIBRARIES={'lib/libbloom.a','lib/bloom.lib','lib/libcrypto.a'}


class ArtifactError(ValueError):
    pass


def digest(data):return hashlib.sha256(data).hexdigest()


def canonical(document):return (json.dumps(document,sort_keys=True,separators=(',',':'))+'\n').encode()


def secret_key():
    try:key=base64.b64decode(os.environ.get('BLOOM_ARTIFACT_KEY',''),validate=True)
    except ValueError:raise ArtifactError('SDK artifact key is invalid')from None
    if len(key)!=32:raise ArtifactError('SDK artifact key must contain 32 bytes')
    return key


def validate_manifest(manifest,target,sdk_version,source_input_sha):
    if (manifest.get('schema_version')!=1 or manifest.get('sdk_version')!=sdk_version
        or manifest.get('source_input_sha256')!=source_input_sha or manifest.get('target')!=target
        or manifest.get('tests')!={'native_build':'passed','required_sdk_semantics':'passed'}):
        raise ArtifactError('SDK manifest identity or required native test outcome mismatch')
    valid_targets={'x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-apple-darwin','aarch64-apple-darwin','x86_64-pc-windows-msvc','aarch64-pc-windows-msvc'}
    if target not in valid_targets:raise ArtifactError('SDK target is not a supported native platform')
    abi=manifest.get('abi',{})
    system='Windows'if 'windows'in target else 'Darwin'if 'apple'in target else 'Linux'
    arch='aarch64'if target.startswith('aarch64-')else'x86_64'
    if abi!=dict(os=system,arch=arch,pointer_width=64,endianness='little'):
        raise ArtifactError('SDK native ABI does not match target')
    if re.fullmatch('[0-9a-f]{64}',source_input_sha)is None:raise ArtifactError('SDK source input hash invalid')
    private_revision=manifest.get('private_source_revision')
    if not isinstance(private_revision,str)or re.fullmatch('[0-9a-f]{40}',private_revision)is None:raise ArtifactError('SDK private source revision identity invalid')
    files=manifest.get('files',[])
    if not isinstance(files,list)or not 9<=len(files)<=12:raise ArtifactError('SDK file inventory count invalid')
    seen=set();total=0
    for item in files:
        name=item.get('path');size=item.get('bytes');checksum=item.get('sha256')
        if name not in FIXED_FILES|LIBRARIES or name in seen or type(size)is not int or not 0<size<=MAX_ARCHIVE:
            raise ArtifactError('SDK contains an unapproved file or size')
        if not isinstance(checksum,str)or len(checksum)!=64 or any(c not in '0123456789abcdef'for c in checksum):raise ArtifactError('SDK file hash invalid')
        seen.add(name);total+=size
    required=FIXED_FILES|({'lib/bloom.lib'}if 'windows' in target else {'lib/libbloom.a'})
    if not required<=seen or total>MAX_EXPANDED:raise ArtifactError('SDK required inventory missing or oversized')
    if 'apple' in target and 'lib/libcrypto.a'not in seen:raise ArtifactError('macOS SDK must include exact tested static Crypto archive')
    expected_libraries={'lib/bloom.lib'}if'windows'in target else{'lib/libbloom.a','lib/libcrypto.a'}if'apple'in target else{'lib/libbloom.a'}
    if seen&LIBRARIES!=expected_libraries:raise ArtifactError('SDK native library inventory mismatch')
    return manifest


def make_envelope(files,identity):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    manifest=dict(identity,schema_version=1,tests={'native_build':'passed','required_sdk_semantics':'passed'},files=[dict(path=name,bytes=len(data),sha256=digest(data))for name,data in sorted(files.items())])
    validate_manifest(manifest,identity['target'],identity['sdk_version'],identity['source_input_sha256'])
    metadata=canonical(manifest)
    stream=io.BytesIO()
    with gzip.GzipFile(filename='',fileobj=stream,mode='wb',mtime=0)as compressed:
        with tarfile.open(fileobj=compressed,mode='w',format=tarfile.USTAR_FORMAT)as archive:
            for name,data in sorted(dict(files,**{'manifest.json':metadata}).items()):
                info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o600;info.mtime=0
                archive.addfile(info,io.BytesIO(data))
    payload=stream.getvalue()
    if len(payload)>MAX_ARCHIVE:raise ArtifactError('SDK archive exceeds encryption bound')
    nonce=os.urandom(12)
    ciphertext=nonce+AESGCM(secret_key()).encrypt(nonce,payload,metadata)
    return ciphertext,metadata


def unpack_envelope(ciphertext,metadata,destination,target,sdk_version,source_input_sha):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not 28<len(ciphertext)<=MAX_ARCHIVE+28 or len(metadata)>65536:raise ArtifactError('SDK envelope size invalid')
    try:
        manifest=json.loads(metadata)
        validate_manifest(manifest,target,sdk_version,source_input_sha)
        payload=AESGCM(secret_key()).decrypt(ciphertext[:12],ciphertext[12:],metadata)
    except ArtifactError:raise
    except Exception:raise ArtifactError('SDK envelope authentication failed')from None
    destination=Path(destination)
    if destination.is_symlink()or(destination.exists()and any(destination.iterdir())):raise ArtifactError('SDK extraction directory must be new and empty')
    # Bound expanded bytes before tar extended-header parsing.
    with gzip.GzipFile(fileobj=io.BytesIO(payload))as compressed:
        expanded=compressed.read(MAX_EXPANDED+1024*1024+1)
    if len(expanded)>MAX_EXPANDED+1024*1024:raise ArtifactError('SDK decompression bound exceeded')
    expected={item['path']:item for item in manifest['files']};seen={}
    with tarfile.open(fileobj=io.BytesIO(expanded),mode='r:')as archive:
        for item in archive:
            if not item.isfile()or item.name not in set(expected)|{'manifest.json'}or item.name in seen:
                raise ArtifactError('SDK archive contains non-allowlisted source, link or duplicate')
            if item.size>MAX_ARCHIVE:raise ArtifactError('SDK member exceeds bound')
            data=archive.extractfile(item).read(item.size+1)
            if item.name=='manifest.json':
                if data!=metadata:raise ArtifactError('Inner SDK manifest mismatch')
            elif len(data)!=expected[item.name]['bytes']or digest(data)!=expected[item.name]['sha256']:
                raise ArtifactError('SDK member hash mismatch')
            seen[item.name]=data
    if set(seen)!=set(expected)|{'manifest.json'}:raise ArtifactError('SDK archive inventory mismatch')
    destination.mkdir(parents=True,exist_ok=True)
    if os.name!='nt':destination.chmod(0o700)
    for name,data in seen.items():
        path=destination.joinpath(*PurePosixPath(name).parts);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o600)
    return manifest


def collect_sdk(source,sdk_source,sdk_output,env):
    files={}
    for name in ['include/bloom.h','bindings/rust/Cargo.toml','bindings/rust/build.rs','bindings/rust/src/lib.rs']:
        path=sdk_source/name
        if path.is_symlink()or not path.is_file():raise ArtifactError('SDK API file missing')
        files[name]=path.read_bytes()
    files['capabilities.json']=(sdk_source/'headspace-capabilities.json').read_bytes()
    for name in ['BloomDB-NOTICE.txt','cJSON-LICENSE.txt','OpenSSL-LICENSE.txt']:
        files['notices/'+name]=(source/'packaging/notices'/name).read_bytes()
    for name in ['libbloom.a','bloom.lib']:
        path=sdk_output/'lib'/name
        if path.is_file()and not path.is_symlink():files['lib/'+name]=path.read_bytes()
    if 'static=crypto'in env['BLOOM_STATIC_LIBS']:
        directories=env.get('BLOOM_EXTRA_LIB_DIRS','').split(os.pathsep)
        matches=[Path(d)/'libcrypto.a'for d in directories if d and(Path(d)/'libcrypto.a').is_file()]
        if len(matches)!=1:raise ArtifactError('Exact tested static Crypto archive unavailable')
        files['lib/libcrypto.a']=matches[0].read_bytes()
    return files


def sdk_link_env(directory,target):
    directory=Path(directory).resolve()
    libraries='bcrypt'if 'windows'in target else 'static=crypto,m,pthread'if 'apple'in target else 'crypto,m,pthread'
    return dict(BLOOM_LIB_DIR=str(directory/'lib'),BLOOM_STATIC='1',BLOOM_STATIC_LIBS=libraries,BLOOM_EXTRA_LIB_DIRS=str(directory/'lib'))


MAX_FAILURE_LOG=16*1024*1024


def encrypt_failure_log(raw,identity,total_bytes=None):
    """Encrypt bounded diagnostics; this format is distinct from an SDK payload."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    required={'source_input_sha256','recipe_revision','app_source_revision','target','version','sdk_version','run_id','worker_sha','phase'}
    if set(identity)!=required:raise ArtifactError('Encrypted diagnostic identity fields invalid')
    for field,length in [('source_input_sha256',64),('recipe_revision',40),('app_source_revision',40),('worker_sha',40)]:
        if not isinstance(identity[field],str)or re.fullmatch('[0-9a-f]{'+str(length)+'}',identity[field])is None:raise ArtifactError('Encrypted diagnostic revision identity invalid')
    if identity['phase']not in ('sdk_build','cargo_test','cargo_build')or type(identity['run_id'])is not int or identity['run_id']<=0:
        raise ArtifactError('Encrypted diagnostic run/phase invalid')
    if identity['target']not in {'x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-apple-darwin','aarch64-apple-darwin','x86_64-pc-windows-msvc','aarch64-pc-windows-msvc'}:raise ArtifactError('Encrypted diagnostic target invalid')
    for field in ['version','sdk_version']:
        if not isinstance(identity[field],str)or re.fullmatch('[0-9A-Za-z.+-]{1,128}',identity[field])is None:raise ArtifactError('Encrypted diagnostic version invalid')
    total=len(raw)if total_bytes is None else total_bytes
    if type(total)is not int or total<len(raw):raise ArtifactError('Encrypted diagnostic size identity invalid')
    payload=raw[-MAX_FAILURE_LOG:]
    metadata=canonical(dict(identity,schema_version=1,purpose='private_build_diagnostics',bytes=len(payload),total_bytes=total,truncated=total>len(payload)))
    nonce=os.urandom(12)
    return nonce+AESGCM(secret_key()).encrypt(nonce,payload,metadata),metadata
