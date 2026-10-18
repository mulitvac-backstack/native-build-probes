"""Consume source-locked durable encrypted SDKs, with no engine-source fallback."""
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

from sdk_artifacts import ArtifactError,MAX_ARCHIVE,unpack_envelope,sdk_link_env

REPOSITORY='mulitvac-backstack/native-build-probes'
TARGETS={'x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-apple-darwin','aarch64-apple-darwin','x86_64-pc-windows-msvc','aarch64-pc-windows-msvc'}
BASE='https://git.multivac.network/backstack.io/headspace/releases/download/bloom-sdk-v'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def read_public(url,maximum):
    opener=urllib.request.build_opener(NoRedirect)
    for _ in range(4):
        parsed=urllib.parse.urlparse(url)
        if parsed.scheme!='https'or parsed.hostname!='git.multivac.network'or parsed.username or parsed.password:
            raise ArtifactError('SDK download redirect is outside canonical public origin')
        try:
            response=opener.open(urllib.request.Request(url,headers={'User-Agent':'Headspace-Native-SDK/1.0'}),timeout=60)
            with response:
                data=response.read(maximum+1)
            if len(data)>maximum:raise ArtifactError('SDK download exceeds bound')
            return data
        except urllib.error.HTTPError as exc:
            if exc.code in (301,302,303,307,308)and exc.headers.get('Location'):
                url=urllib.parse.urljoin(url,exc.headers['Location']);continue
            raise ArtifactError('Canonical encrypted SDK asset is unavailable')from None
        except urllib.error.URLError:raise ArtifactError('Canonical encrypted SDK asset download failed')from None
    raise ArtifactError('SDK redirect count exceeded')


def read_lock(source):
    path=source/'docs/release/bloom-sdk-lock.json'
    if path.is_symlink()or not path.is_file()or path.stat().st_size>65536:raise ArtifactError('Source-pinned complete native SDK lock is required')
    lock=json.loads(path.read_text());pin=json.loads((source/'docs/release/bloom-sdk-input.json').read_text())
    if not isinstance(lock,dict)or not isinstance(pin,dict):raise ArtifactError('SDK source lock/input must be objects')
    private_revision=pin.get('private_source_revision')
    if not isinstance(private_revision,str)or re.fullmatch('[0-9a-f]{40}',private_revision)is None:raise ArtifactError('SDK input must pin private source revision')
    if lock.get('schema_version')!=1 or lock.get('sdk_version')!=pin.get('sdk_version')or lock.get('source_input_sha256')!=pin.get('archive_sha256'):
        raise ArtifactError('SDK lock does not match immutable source/version input')
    if not isinstance(lock.get('targets'),dict)or set(lock.get('targets',{}))!=TARGETS:raise ArtifactError('SDK lock must include all six native targets')
    producer=lock.get('producer',{})
    if producer.get('repository')!=REPOSITORY or producer.get('workflow')!='bloom-sdk.yml'or type(producer.get('run_id'))is not int or producer['run_id']<=0:
        raise ArtifactError('SDK producer repository/workflow/run identity invalid')
    for key in ['head_sha','recipe_revision']:
        if not isinstance(producer.get(key),str)or re.fullmatch('[0-9a-f]{40}',producer[key])is None:raise ArtifactError('SDK producer immutable revision invalid')
    for target,entry in lock['targets'].items():
        if not isinstance(entry,dict):raise ArtifactError('SDK target lock entry must be an object')
        if entry.get('artifact_name')!='bloom-sdk-'+lock['sdk_version']+'-'+target:raise ArtifactError('SDK artifact name/target/version mismatch')
        for field in ['ciphertext_sha256','manifest_sha256']:
            if not isinstance(entry.get(field),str)or re.fullmatch('[0-9a-f]{64}',entry[field])is None:raise ArtifactError('SDK lock digest invalid')
    return lock


def consume(source,target,download=read_public):
    lock=read_lock(source);entry=lock['targets'][target];stem=entry['artifact_name']
    base=BASE+urllib.parse.quote(lock['sdk_version'],safe='')+'/'
    ciphertext=download(base+urllib.parse.quote(stem+'.aesgcm',safe=''),MAX_ARCHIVE+28)
    metadata=download(base+urllib.parse.quote(stem+'.manifest.json',safe=''),65536)
    if hashlib.sha256(ciphertext).hexdigest()!=entry['ciphertext_sha256']or hashlib.sha256(metadata).hexdigest()!=entry['manifest_sha256']:
        raise ArtifactError('Durable encrypted SDK asset checksum mismatch')
    manifest=json.loads(metadata)
    pin=json.loads((source/'docs/release/bloom-sdk-input.json').read_text())
    for field in ['private_source_revision','private_source_subdirectory']:
        if pin.get(field)and manifest.get(field)!=pin[field]:raise ArtifactError('SDK private source identity differs from source input pin')
    if manifest.get('producer')!=lock['producer']:raise ArtifactError('SDK manifest producer differs from source lock')
    destination=source/'.private/bloomdb'
    if (source/'.private').is_symlink()or destination.is_symlink()or not destination.resolve().is_relative_to(source.resolve()):
        raise ArtifactError('SDK destination escapes source containment')
    unpack_envelope(ciphertext,metadata,destination,target,lock['sdk_version'],lock['source_input_sha256'])
    return sdk_link_env(destination,target),dict(sdk_version=lock['sdk_version'],source_input_sha256=lock['source_input_sha256'],producer=lock['producer'],ciphertext_sha256=entry['ciphertext_sha256'],native_tests=manifest['tests'],engine_recompiled=False)
