"""Authenticated Bloom-owned SDK profile input; no application source dependency."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import zlib

from sdk_artifacts import ArtifactError

REPOSITORY = 'https://git.multivac.network/backstack.io/bloomdb'
MAX_ARCHIVE = 512 * 1024
MAX_EXPANDED = 16 * 1024 * 1024
FIXED_FILES = {'sdk-profile.json', 'source-inventory.json', 'recipe/build_bloom.py', 'recipe/LICENSE',
               'recipe/bloom-sdk/CMakeLists.txt', 'recipe/bloom-sdk/platform.c',
               'recipe/bloom-sdk/platform.h', 'recipe/bloom-sdk/sdk_smoke.c',
               'notices/BloomDB-NOTICE.txt', 'notices/cJSON-LICENSE.txt', 'notices/OpenSSL-LICENSE.txt'}
ALLOWED_ENV = {'BLOOM_LIB_DIR', 'BLOOM_STATIC', 'BLOOM_STATIC_LIBS', 'BLOOM_EXTRA_LIB_DIRS'}


def semver(value):
    pattern = r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?'
    match = re.fullmatch(pattern, value) if isinstance(value, str) and len(value) <= 128 else None
    if not match or (match[4] and any(p.isdigit() and len(p) > 1 and p.startswith('0') for p in match[4].split('.'))):
        raise ArtifactError('Bloom SDK version must be exact SemVer')
    return value


def revision(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{40}', value) is None:
        raise ArtifactError('Bloom source revision must be immutable')
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative_name(name):
    return (isinstance(name, str) and 0 < len(name) <= 240 and not PurePosixPath(name).is_absolute()
            and re.fullmatch('[A-Za-z0-9_./-]+', name) is not None
            and '\\' not in name and ':' not in name and all(p not in ('', '.', '..') for p in name.split('/')))


def read_pin(path, expected_revision, expected_version, configured_sha):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ArtifactError('Bloom source-owned profile pin is missing or oversized')
    pin = json.loads(path.read_text())
    if not isinstance(pin, dict) or pin.get('schema_version') != 2:
        raise ArtifactError('Bloom SDK profile pin schema is unsupported')
    source = pin.get('source', {})
    if (not isinstance(source, dict) or source.get('repository') != REPOSITORY
            or source.get('revision') != revision(expected_revision) or source.get('subdirectory') != 'sdk/embedded'):
        raise ArtifactError('Bloom profile source authority differs from requested source')
    if pin.get('sdk_version') != semver(expected_version):
        raise ArtifactError('Bloom profile version differs from requested SDK version')
    for field in ('archive_sha256', 'profile_sha256', 'inventory_sha256'):
        if not isinstance(pin.get(field), str) or re.fullmatch('[0-9a-f]{64}', pin[field]) is None:
            raise ArtifactError('Bloom profile pin digest is invalid')
    if pin['archive_sha256'] != configured_sha:
        raise ArtifactError('Configured Bloom input differs from the immutable profile pin')
    if (not isinstance(pin.get('binding_package_version'), str) or not isinstance(pin.get('capability_profile'), str)
            or re.fullmatch('[a-z0-9][a-z0-9_-]{0,79}', pin['capability_profile']) is None):
        raise ArtifactError('Bloom profile capability and binding versions must be pinned')
    semver(pin['binding_package_version'])
    return pin


def extract_profile(encoded, pin, destination):
    encoded = Path(encoded)
    if encoded.is_symlink() or not encoded.is_file() or encoded.stat().st_size > MAX_ARCHIVE * 2:
        raise ArtifactError('Bloom profile encoded input is unavailable or oversized')
    try:
        payload = base64.b64decode(encoded.read_bytes(), validate=True)
    except ValueError:
        raise ArtifactError('Bloom profile encoding is invalid') from None
    if len(payload) > MAX_ARCHIVE or digest(payload) != pin['archive_sha256']:
        raise ArtifactError('Bloom profile archive hash or size differs from source pin')
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
            expanded = compressed.read(MAX_EXPANDED + 1)
        if len(expanded) > MAX_EXPANDED:
            raise ArtifactError('Bloom profile expanded size exceeds bound')
        files = {}
        with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
            for item in archive:
                if len(files) >= 200 or not item.isfile() or not item.name.startswith('bloomdb-sdk/'):
                    raise ArtifactError('Bloom profile archive contains an unsupported member')
                name = item.name.removeprefix('bloomdb-sdk/')
                if (not relative_name(name) or name in files or item.size > MAX_EXPANDED
                        or (name not in FIXED_FILES and not name.startswith('input/bloomdb/'))):
                    raise ArtifactError('Bloom profile member is outside the strict payload layout')
                files[name] = archive.extractfile(item).read(item.size + 1)
                if len(files[name]) != item.size:
                    raise ArtifactError('Bloom profile member size is inconsistent')
    except (OSError, EOFError, tarfile.TarError, zlib.error):
        raise ArtifactError('Bloom profile archive encoding is invalid') from None
    if not FIXED_FILES <= set(files):
        raise ArtifactError('Bloom profile required recipe, metadata or notices are missing')
    if (digest(files['sdk-profile.json']) != pin['profile_sha256']
            or digest(files['source-inventory.json']) != pin['inventory_sha256']):
        raise ArtifactError('Bloom profile metadata differs from source pin')
    profile = json.loads(files['sdk-profile.json'])
    if not isinstance(profile, dict):
        raise ArtifactError('Bloom profile metadata must be an object')
    for field in ('sdk_version', 'binding_package_version', 'capability_profile'):
        if profile.get(field) != pin[field]:
            raise ArtifactError('Bloom-owned profile metadata differs from its pin')
    inventory = json.loads(files['source-inventory.json'])
    if not isinstance(inventory, dict) or inventory.get('schema_version') != 1 or not isinstance(inventory.get('files'), list):
        raise ArtifactError('Bloom profile inventory schema is invalid')
    seen = set()
    for entry in inventory['files']:
        name = entry.get('path') if isinstance(entry, dict) else None
        if (not relative_name(name) or name in seen or name == 'source-inventory.json' or name not in files
                or type(entry.get('size')) is not int or entry['size'] != len(files[name])
                or entry.get('sha256') != digest(files[name])):
            raise ArtifactError('Bloom profile inventory has duplicate, missing or mismatched bytes')
        seen.add(name)
    if seen != set(files) - {'source-inventory.json'}:
        raise ArtifactError('Bloom profile inventory must cover every recipe, notice and input file')
    destination = Path(destination)
    if destination.is_symlink() or (destination.exists() and any(destination.iterdir())):
        raise ArtifactError('Bloom profile destination must be new and empty')
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve() / 'bloomdb-sdk'
    root.mkdir(mode=0o700)
    for name, data in files.items():
        path = root.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
    return root


def private_env(env):
    return {k: v for k, v in env.items() if not k.startswith('BLOOM_SDK_')
            and k not in ('BLOOM_ARTIFACT_KEY', 'BLOOM_INPUT_CHUNK', 'GH_TOKEN', 'GITHUB_TOKEN')}


def append_input(path, index, chunk, count):
    if type(index) is not int or type(count) is not int or not 1 <= count <= 24 or not 1 <= index <= 24:
        raise ArtifactError('Bloom private input chunk index or count is invalid')
    if index > count:
        if chunk:
            raise ArtifactError('Bloom input has unexpected extra chunks')
        return
    if not isinstance(chunk, str) or not chunk or len(chunk) > 12288 or re.fullmatch('[A-Za-z0-9+/=]+', chunk) is None:
        raise ArtifactError('Bloom private input chunk is invalid')
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ArtifactError('Bloom private input path is not owned')
    if index == 1:
        path.write_text('', encoding='ascii')
        path.chmod(0o600)
    if not path.is_file():
        raise ArtifactError('Bloom private input assembly is unavailable')
    with path.open('a', encoding='ascii') as handle:
        handle.write(chunk)
    if path.stat().st_size > MAX_ARCHIVE * 2:
        raise ArtifactError('Bloom private input assembly exceeds bound')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['append-input'])
    parser.add_argument('--index', type=int, required=True)
    parser.add_argument('--file', type=Path, required=True)
    args = parser.parse_args()
    try:
        append_input(args.file, args.index, os.environ.get('BLOOM_INPUT_CHUNK', ''), int(os.environ.get('BLOOM_SDK_CHUNKS', '0')))
    except (ArtifactError, OSError, ValueError):
        raise SystemExit('Bloom private input assembly failed') from None
