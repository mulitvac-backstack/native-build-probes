"""Consume source-locked durable encrypted SDKs, with no engine-source fallback."""
import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

from sdk_artifacts import ArtifactError,MAX_ARCHIVE,unpack_envelope,sdk_link_env
from bloom_profile import semver

REPOSITORY='mulitvac-backstack/native-build-probes'
TARGETS={'x86_64-unknown-linux-gnu','aarch64-unknown-linux-gnu','x86_64-apple-darwin','aarch64-apple-darwin','x86_64-pc-windows-msvc','aarch64-pc-windows-msvc'}
BASE='https://git.multivac.network/api/packages/backstack.io/generic/bloomdb-sdk/'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None


def read_public(url,maximum):
    parsed=urllib.parse.urlparse(url)
    if (parsed.scheme!='https'or parsed.netloc!='git.multivac.network'or parsed.username or parsed.password
        or parsed.query or parsed.fragment or not parsed.path.startswith('/api/packages/backstack.io/generic/bloomdb-sdk/')):
        raise ArtifactError('SDK asset is outside the canonical Bloom ciphertext distribution')
    opener=urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(urllib.request.Request(url,headers={'User-Agent':'Bloom-SDK-Consumer/2.0'}),timeout=60)as response:
            data=response.read(maximum+1)
        if len(data)>maximum:raise ArtifactError('SDK download exceeds bound')
        return data
    except urllib.error.HTTPError:
        raise ArtifactError('Canonical Bloom SDK asset is unavailable; redirects are forbidden')from None
    except urllib.error.URLError:
        raise ArtifactError('Canonical Bloom SDK asset download failed')from None


def read_lock(source):
    path=source/'docs/release/bloom-sdk-lock.json'
    if path.is_symlink()or not path.is_file()or path.stat().st_size>65536:raise ArtifactError('Source-pinned complete native SDK lock is required')
    lock=json.loads(path.read_text());pin=json.loads((source/'docs/release/bloom-sdk-input.json').read_text())
    if not isinstance(lock,dict)or not isinstance(pin,dict):raise ArtifactError('SDK source lock/input must be objects')
    semver(lock.get('sdk_version'))
    private_revision=pin.get('private_source_revision')
    if (not isinstance(private_revision,str)or re.fullmatch('[0-9a-f]{40}',private_revision)is None
        or pin.get('private_source_subdirectory')!='sdk/embedded/input/bloomdb'):raise ArtifactError('SDK input must pin private source revision')
    if lock.get('schema_version')!=2 or lock.get('sdk_version')!=pin.get('sdk_version')or lock.get('source_input_sha256')!=pin.get('archive_sha256'):
        raise ArtifactError('SDK lock does not match immutable source/version input')
    release=lock.get('release',{})
    if (not isinstance(release,dict)or set(release)!={'repository','tag','revision','distribution'}
        or release.get('repository')!='backstack.io/bloomdb' or release.get('tag')!='sdk-v'+lock['sdk_version']
        or release.get('revision')!=private_revision
        or release.get('distribution')!=dict(kind='gitea_generic',owner='backstack.io',package='bloomdb-sdk',version=lock['sdk_version'])):
        raise ArtifactError('SDK canonical Bloom release or ciphertext distribution identity invalid')
    if not isinstance(lock.get('targets'),dict)or set(lock.get('targets',{}))!=TARGETS:raise ArtifactError('SDK lock must include all six native targets')
    producer=lock.get('producer',{})
    if not isinstance(producer,dict)or producer.get('repository')!=REPOSITORY or producer.get('workflow')!='bloom-sdk.yml'or type(producer.get('run_id'))is not int or producer['run_id']<=0:
        raise ArtifactError('SDK producer repository/workflow/run identity invalid')
    if (producer.get('recipe_repository')!='backstack.io/bloomdb'
        or producer.get('recipe_revision')!=release['revision']
        or producer.get('profile_path')!='sdk/embedded/sdk-profile.json'):
        raise ArtifactError('SDK producer recipe must belong to the canonical Bloom source revision')
    for key in ['head_sha','recipe_revision']:
        if not isinstance(producer.get(key),str)or re.fullmatch('[0-9a-f]{40}',producer[key])is None:raise ArtifactError('SDK producer immutable revision invalid')
    for target,entry in lock['targets'].items():
        if not isinstance(entry,dict):raise ArtifactError('SDK target lock entry must be an object')
        if entry.get('artifact_name')!='bloom-sdk-'+lock['sdk_version']+'-'+target:raise ArtifactError('SDK artifact name/target/version mismatch')
        for field in ['ciphertext_sha256','manifest_sha256','build_receipt_sha256']:
            if not isinstance(entry.get(field),str)or re.fullmatch('[0-9a-f]{64}',entry[field])is None:raise ArtifactError('SDK lock digest invalid')
    return lock


def consume(source,target,download=read_public):
    lock=read_lock(source);entry=lock['targets'][target];stem=entry['artifact_name']
    base=BASE+urllib.parse.quote(lock['sdk_version'],safe='')+'/'
    ciphertext=download(base+urllib.parse.quote(stem+'.aesgcm',safe=''),MAX_ARCHIVE+28)
    metadata=download(base+urllib.parse.quote(stem+'.manifest.json',safe=''),65536)
    build_data=download(base+'bloom-build-'+target+'.json',65536)
    if (hashlib.sha256(ciphertext).hexdigest()!=entry['ciphertext_sha256']or hashlib.sha256(metadata).hexdigest()!=entry['manifest_sha256']
        or hashlib.sha256(build_data).hexdigest()!=entry['build_receipt_sha256']):
        raise ArtifactError('Durable encrypted SDK asset checksum mismatch')
    manifest=json.loads(metadata)
    pin=json.loads((source/'docs/release/bloom-sdk-input.json').read_text())
    for field in ['private_source_revision','private_source_subdirectory']:
        if pin.get(field)and manifest.get(field)!=pin[field]:raise ArtifactError('SDK private source identity differs from source input pin')
    if manifest.get('producer')!=lock['producer']:raise ArtifactError('SDK manifest producer differs from source lock')
    build=json.loads(build_data)
    expected=dict(schema_version=1,source_repository='backstack.io/bloomdb',recipe_revision=lock['release']['revision'],target=target,sdk_version=lock['sdk_version'],source_input_sha256=lock['source_input_sha256'],producer=lock['producer'],private_source_revision=manifest.get('private_source_revision'),private_source_subdirectory=manifest.get('private_source_subdirectory'),artifact_name=stem,status='passed',phase='completed',tests=manifest.get('tests'))
    if not isinstance(build,dict)or any(build.get(key)!=value for key,value in expected.items()):raise ArtifactError('SDK native build receipt differs from the locked producer or required tests')
    destination=source/'.private/bloomdb'
    if (source/'.private').is_symlink()or destination.is_symlink()or not destination.resolve().is_relative_to(source.resolve()):
        raise ArtifactError('SDK destination escapes source containment')
    unpack_envelope(ciphertext,metadata,destination,target,lock['sdk_version'],lock['source_input_sha256'])
    return sdk_link_env(destination,target),dict(sdk_version=lock['sdk_version'],source_input_sha256=lock['source_input_sha256'],release=lock['release'],producer=lock['producer'],ciphertext_sha256=entry['ciphertext_sha256'],build_receipt_sha256=entry['build_receipt_sha256'],native_tests=manifest['tests'],engine_recompiled=False)
