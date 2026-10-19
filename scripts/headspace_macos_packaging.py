#!/usr/bin/env python3
"""Package qualified, immutable Mac executables; never compile product or SDK."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe
from headspace_source_build import BuildFailure, fetch_source, run

ROOT = Path(__file__).resolve().parents[1]
SOURCE = '1e218062387de1b712576e25fdc1bc4d8a0ac395'
RUN = 39164407324
WORKER = 'a25c04c06731a067a27dec5d9317ee67a2325c11'
REPOSITORY = 'mulitvac-backstack/native-build-probes'
OWNER = 'https://git.multivac.network/backstack.io/headspace'
VERSION = '0.1.0-alpha.1'
TARGETS = {'macos-15-intel': 'x86_64-apple-darwin', 'macos-15': 'aarch64-apple-darwin'}


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def document(path, maximum=65536):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise BuildFailure('invalid_receipt', 'Receipt must be a bounded regular file')
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise BuildFailure('invalid_receipt', 'Receipt must be a JSON object')
    return value


def load_profile(path):
    profile = document(path)
    if (profile.get('schema_version') != 1 or profile.get('owner_repository') != OWNER
            or profile.get('binary_source_revision') != SOURCE or profile.get('binary_version') != VERSION
            or profile.get('input_run_id') != RUN or profile.get('input_worker_revision') != WORKER
            or profile.get('input_repository') != REPOSITORY
            or profile.get('recipe_path') != 'scripts/package-macos.py'
            or not re.fullmatch('[0-9a-f]{40}', profile.get('recipe_revision', ''))
            or not re.fullmatch('[0-9a-f]{64}', profile.get('recipe_sha256', ''))
            or set(profile.get('targets', {})) != set(TARGETS)):
        raise BuildFailure('profile_identity', 'Only the pinned Headspace Mac packaging operation is allowed')
    for label, target in TARGETS.items():
        item = profile['targets'][label]
        if (item.get('target') != target or item.get('artifact_name') != f'headspace-{label}-{SOURCE}'
                or not re.fullmatch('[0-9a-f]{64}', item.get('executable_sha256', ''))):
            raise BuildFailure('profile_identity', 'Pinned Mac artifact identity differs')
    return profile


def recipe_environment(environ):
    return {name: value for name, value in environ.items()
            if not name.startswith(('BLOOM_', 'OPENAI_', 'AWS_', 'CODEX_', 'GH_'))
            and name not in ('GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN')}


def validate_input(directory, profile, label):
    target = TARGETS[label]
    executable = f'headspace-{VERSION}-{target}'
    expected = {executable, f'inventory-{target}.json', f'build-{target}.json',
                f'verify-{target}-binary.json', f'verify-native-{target}-binary.json'}
    if set(path.name for path in directory.iterdir()) != expected:
        raise BuildFailure('artifact_files', 'Input artifact must contain exactly the five qualified files')
    for path in directory.iterdir():
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
            raise BuildFailure('artifact_files', 'Unsafe or oversized artifact input')
    binary = directory / executable
    digest = sha(binary)
    with binary.open('rb') as stream:
        head = stream.read(8)
    cpu = 0x1000007 if target.startswith('x86_64') else 0x100000c
    if (head[:4] != b'\xcf\xfa\xed\xfe' or int.from_bytes(head[4:8], 'little') != cpu
            or digest != profile['targets'][label]['executable_sha256']):
        raise BuildFailure('binary_identity', 'Input Mach-O architecture or immutable hash differs')
    inventory = document(directory / f'inventory-{target}.json')
    files = inventory.get('files', [])
    if (inventory.get('source_revision') != SOURCE or inventory.get('target') != target
            or inventory.get('version') != VERSION or len(files) != 1
            or files[0].get('path') != executable or files[0].get('sha256') != digest
            or files[0].get('bytes') != binary.stat().st_size):
        raise BuildFailure('input_inventory', 'Qualified input inventory differs')
    build = document(directory / f'build-{target}.json')
    if (build.get('source_revision') != SOURCE or build.get('target') != target
            or build.get('runner') != label or build.get('status') != 'passed'
            or build.get('cargo_test') != 'passed' or build.get('cargo_build') != 'passed'):
        raise BuildFailure('input_build', 'Qualified native build receipt differs')
    for mode in ('audit', 'native'):
        prefix = 'verify-native-' if mode == 'native' else 'verify-'
        proof = document(directory / f'{prefix}{target}-binary.json')
        cli = proof.get('cli', {})
        if (proof.get('source_revision') != SOURCE or proof.get('target') != target
                or proof.get('runner') != label or proof.get('mode') != mode
                or proof.get('audit', {}).get('sha256') != digest or cli.get('status') != 'passed'
                or cli.get('embedded_notices') != 7 or cli.get('mcp', {}).get('status') != 'passed'
                or cli['mcp'].get('embedded_image_bytes') is not True):
            raise BuildFailure('input_qualification', 'Qualified native CLI/MCP receipt differs')
        if mode == 'native':
            gui = proof.get('native_gui', {})
            engine = gui.get('native_engine', {})
            if (proof.get('status') != 'passed_bounded_native_checks' or gui.get('status') != 'passed'
                    or gui.get('working_recovery') is not True or gui.get('portable_roundtrip') is not True
                    or engine.get('draw_total_ms', {}).get('count', 0) < 3
                    or engine.get('platform_submit_ms', {}).get('count', 0) < 3):
                raise BuildFailure('input_qualification', 'Native draw/save/recovery proof is incomplete')
    binary.chmod(0o755)
    return binary


def qualified_outputs(directory, profile, label):
    """The recipe's closed output set is copied only after hash/size checks."""
    target = TARGETS[label]
    # Owner recipe publishes a small inventory alongside one DMG and receipt.
    inventory_path = directory / f'macos-package-inventory-{target}-r1.json'
    inventory = document(inventory_path)
    if (inventory.get('schema_version') != 1 or inventory.get('owner_repository') != OWNER
            or inventory.get('source_revision') != SOURCE or inventory.get('target') != target
            or inventory.get('version') != VERSION or inventory.get('package_revision') != 1
            or inventory.get('recipe_revision') != profile['recipe_revision']
            or inventory.get('recipe_sha256') != profile['recipe_sha256']
            or inventory.get('native_runner') != label or inventory.get('original_release_assets_unchanged') is not True
            or inventory.get('status') != 'passed_native_macos_package_checks'):
        raise BuildFailure('output_identity', 'Mac package inventory identity differs')
    entries = inventory.get('files', [])
    if len(entries) != 1:
        raise BuildFailure('output_files', 'Exactly one DMG is required per native Mac target')
    name = f'headspace-{VERSION}-pkg1-{target}.dmg'
    entry = entries[0]
    path = directory / name
    if set(p.name for p in directory.iterdir()) != {name, inventory_path.name}:
        raise BuildFailure('output_files', 'Only the DMG and bounded inventory may leave the recipe')
    if (entry.get('path') != name or entry.get('format') != 'dmg' or path.is_symlink()
            or not path.is_file() or not 1 <= path.stat().st_size <= 256 * 1024 * 1024
            or entry.get('bytes') != path.stat().st_size or entry.get('sha256') != sha(path)):
        raise BuildFailure('output_files', 'DMG file identity/hash differs')
    identity = entry.get('normalized_code_identity', {})
    signing = entry.get('signing', {})
    native = entry.get('native_verification', {})
    gui = native.get('native_gui', {})
    engine = gui.get('native_gui', {}).get('native_engine', {})
    packaged_sha = entry.get('packaged_executable_sha256', '')
    if (entry.get('input_executable_sha256') != profile['targets'][label]['executable_sha256']
            or not re.fullmatch('[0-9a-f]{64}', packaged_sha)
            or entry.get('bundle', {}).get('files', {}).get('Contents/MacOS/headspace', {}).get('sha256') != packaged_sha
            or identity.get('status') != 'passed'
            or not re.fullmatch('[0-9a-f]{64}', identity.get('input_unsigned_sha256', ''))
            or identity.get('input_unsigned_sha256') != identity.get('packaged_unsigned_sha256')
            or entry.get('normalized_code_sha256') != identity.get('input_unsigned_sha256')
            or signing != dict(kind='ad_hoc', bundle_seal_verified=True, developer_id=False, notarized=False)
            or any(native.get(field) != 'passed' for field in ('dmg_integrity','read_only_mount','application_bundle_layout','clean_copy_install','version','removal'))
            or native.get('embedded_notices') != 7 or native.get('synthetic_user_data_preserved') is not True
            or native.get('mcp', {}).get('status') != 'passed' or native['mcp'].get('embedded_image_bytes') is not True
            or gui.get('native_gui', {}).get('status') != 'passed'
            or gui['native_gui'].get('working_recovery') is not True or gui['native_gui'].get('portable_roundtrip') is not True
            or engine.get('draw_total_ms', {}).get('count', 0) < 3 or engine.get('platform_submit_ms', {}).get('count', 0) < 3):
        raise BuildFailure('output_qualification', 'Sealed bundle code identity or native package qualification is incomplete')
    return inventory, [path, inventory_path]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', required=True, choices=TARGETS)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    profile = load_profile(ROOT / 'profiles/headspace-macos-packaging.json')
    label = args.runner
    report = dict(schema_version=1, source_revision=SOURCE, version=VERSION,
                  recipe_revision=profile['recipe_revision'], target=TARGETS[label], runner=label,
                  input_run_id=RUN, cargo_invoked=False, sdk_invoked=False, status='failed', phase='native_identity')
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        identity = probe.machine_identity()
        probe.validate_native(label, identity['os'], identity['native_arch'], identity['process_arch'], identity['translated'])
        report['native_identity'] = identity
        with tempfile.TemporaryDirectory(prefix='headspace-mac-package-') as temporary:
            work = Path(temporary); incoming = work / label; incoming.mkdir()
            report['phase'] = 'qualified_input'
            token_env = dict(os.environ)
            run_identity = json.loads(run(['gh', 'api', f'repos/{REPOSITORY}/actions/runs/{RUN}', '--jq',
                '{status,conclusion,head_sha,path,event}'], 'input_run', env=token_env, timeout=60))
            if run_identity != dict(status='completed', conclusion='success', head_sha=WORKER,
                                    path='.github/workflows/headspace-release.yml', event='workflow_dispatch'):
                raise BuildFailure('input_run', 'Original qualified run identity differs')
            run(['gh', 'run', 'download', str(RUN), '-R', REPOSITORY, '-n', profile['targets'][label]['artifact_name'],
                 '-D', str(incoming)], 'artifact_download', env=token_env, timeout=180)
            binary = validate_input(incoming, profile, label)
            report['input_executable_sha256'] = sha(binary)
            report['phase'] = 'owner_source'
            env = recipe_environment(os.environ)
            source = work / 'owner-source'
            def owner_run(command, phase, **kwargs):
                kwargs['env'] = dict(env, GIT_TERMINAL_PROMPT='0', GCM_INTERACTIVE='Never')
                return run(command, phase, **kwargs)
            fetch_source(source, profile['recipe_revision'], execute=owner_run)
            recipe = source / profile['recipe_path']
            if recipe.is_symlink() or not recipe.is_file() or sha(recipe) != profile['recipe_sha256']:
                raise BuildFailure('recipe_identity', 'Owner recipe hash differs')
            candidate = work / 'candidate'
            report['phase'] = 'package_and_verify'
            run([sys.executable, str(recipe), '--artifacts', str(incoming), '--output', str(candidate),
                 '--recipe-revision', profile['recipe_revision'], '--target', TARGETS[label]],
                'native_dmg_package_and_verification', cwd=source, env=env, timeout=600)
            report['phase'] = 'output_audit'
            inventory, outputs = qualified_outputs(candidate, profile, label)
            for path in outputs:
                shutil.copyfile(path, args.output / path.name)
            report.update(status='passed', phase='completed', package_inventory_sha256=sha(outputs[1]),
                          dmg_sha256=inventory['files'][0]['sha256'])
    except (BuildFailure, probe.ProbeError, OSError, ValueError, KeyError) as error:
        report['blocker'] = 'Native packaging or bounded qualification failed; no raw logs or executables forwarded'
        if isinstance(error, BuildFailure):
            report['failure_code'] = error.code
    path = args.output / f'build-macos-package-{TARGETS[label]}.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(status=report['status'], target=report['target'], phase=report['phase'])))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
