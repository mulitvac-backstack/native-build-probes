#!/usr/bin/env python3
"""Six native package jobs from one completed executable run; no app/SDK builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe
from headspace_source_build import BuildFailure, fetch_source, stop_child

REPOSITORY = 'mulitvac-backstack/native-build-probes'
OWNER = 'https://git.multivac.network/backstack.io/headspace'
WORKFLOW = '.github/workflows/headspace-release.yml'
TARGETS = probe.TARGETS
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_BINARY = 512 * 1024 * 1024
MAX_RECEIPT = 131072
MAX_OUTPUT = 1024 * 1024 * 1024


def require(condition, code):
    if not condition: raise BuildFailure(code, 'Native packaging boundary rejected input or output')


def revision(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value) is not None, 'invalid_revision')
    return value


def semver(value):
    require(isinstance(value, str) and len(value) <= 128, 'invalid_version')
    match = re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?', value)
    require(match is not None and not (match[4] and any(x.isdigit() and len(x) > 1 and x[0] == '0' for x in match[4].split('.'))), 'invalid_version')
    return value


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''): digest.update(block)
    return digest.hexdigest()


def document(path):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_RECEIPT, 'receipt_bounds')
    value = json.loads(path.read_text(encoding='utf-8'))
    require(isinstance(value, dict), 'receipt_object')
    return value


def recipe_environment(environ):
    """Allow only native tools/runtime and the disposable runner context."""
    names = {'PATH', 'HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'TMP', 'TEMP', 'TMPDIR',
        'SYSTEMROOT', 'SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT', 'APPDATA', 'LOCALAPPDATA',
        'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'CommonProgramFiles', 'NUMBER_OF_PROCESSORS',
        'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER', 'LANG', 'LC_ALL', 'TZ', 'SHELL',
        'DOTNET_ROOT', 'DOTNET_ROOT_X64', 'DOTNET_ROOT_ARM64', 'DOTNET_MULTILEVEL_LOOKUP',
        'SDKROOT', 'DEVELOPER_DIR', 'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'RUNNER_TEMP',
        'RUNNER_OS', 'RUNNER_ARCH', 'CI', 'DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR'}
    env = {name: value for name, value in environ.items() if name in names}
    env.update(GIT_TERMINAL_PROMPT='0', GCM_INTERACTIVE='Never', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull)
    return env


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl): return None


class Github:
    def __init__(self, token):
        require(isinstance(token, str) and 1 <= len(token) <= 4096, 'readonly_github_token_missing')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, suffix):
        require(suffix.startswith('/actions/runs/') or suffix.startswith('/actions/artifacts/'), 'github_endpoint')
        request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY + suffix,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'Headspace-native-packaging'})
        return self.opener.open(request, timeout=60)

    def json(self, suffix):
        with self.request(suffix) as response:
            data = response.read(1024 * 1024 + 1)
        require(len(data) <= 1024 * 1024, 'github_response_bounds')
        value = json.loads(data)
        require(isinstance(value, dict), 'github_response_object')
        return value

    def archive(self, artifact_id, destination):
        require(type(artifact_id) is int and artifact_id > 0, 'artifact_id')
        try:
            response = self.request(f'/actions/artifacts/{artifact_id}/zip')
        except urllib.error.HTTPError as error:
            if error.code != 302: raise
            url = error.headers.get('Location', ''); error.close(); validate_blob_url(url)
            # Deliberately create a NEW request with NO GitHub authorization.
            response = self.opener.open(urllib.request.Request(url, headers={'User-Agent': 'Headspace-native-packaging'}), timeout=60)
        with response, destination.open('xb') as output:
            declared = response.headers.get('Content-Length')
            require(declared is None or (declared.isdigit() and int(declared) <= MAX_ARCHIVE), 'archive_download_bounds')
            total = 0; deadline = time.monotonic() + 180
            while True:
                block = response.read(1024 * 1024)
                if not block: break
                total += len(block); require(total <= MAX_ARCHIVE and time.monotonic() < deadline, 'archive_download_bounds'); output.write(block)
            require(total > 0, 'archive_empty')


def validate_blob_url(url):
    parsed = urllib.parse.urlsplit(url); host = parsed.hostname or ''
    require(parsed.scheme == 'https' and parsed.port in (None, 443) and parsed.username is None
        and parsed.password is None and not parsed.fragment and
        (host.endswith('.blob.core.windows.net') or host.endswith('.actions.githubusercontent.com')),
        'artifact_redirect_host')


def run_metadata(doc, run_id, source, version):
    require(doc.get('id') == run_id and doc.get('status') == 'completed' and doc.get('conclusion') == 'success'
        and doc.get('event') == 'workflow_dispatch' and doc.get('path') == WORKFLOW
        and doc.get('display_title') == f'Headspace {version} @ {source}'
        and doc.get('repository', {}).get('full_name') == REPOSITORY
        and doc.get('repository', {}).get('private') is False, 'input_run_identity')
    return revision(doc.get('head_sha'))


def artifact_set(doc, run_id, source, worker):
    rows = doc.get('artifacts', [])
    expected = {f'headspace-{label}-{source}': label for label in TARGETS}
    require(doc.get('total_count') == 6 and len(rows) == 6 and {x.get('name') for x in rows} == set(expected), 'input_artifact_set')
    result = {}
    for row in rows:
        name = row['name']; provenance = row.get('workflow_run', {})
        require(type(row.get('id')) is int and row['id'] > 0 and row.get('expired') is False
            and type(row.get('size_in_bytes')) is int and 1 <= row['size_in_bytes'] <= MAX_ARCHIVE
            and provenance.get('id') == run_id and provenance.get('head_sha') == worker,
            'input_artifact_identity')
        result[expected[name]] = row
    require(len({r['id'] for r in rows}) == 6, 'duplicate_artifact_id')
    return result


def input_names(target, version):
    executable = f'headspace-{version}-{target}' + ('.exe' if 'windows' in target else '')
    return {executable, f'inventory-{target}.json', f'build-{target}.json',
            f'verify-{target}-binary.json', f'verify-native-{target}-binary.json'}


def extract_archive(archive, directory, target, version):
    expected = input_names(target, version); directory.mkdir()
    with zipfile.ZipFile(archive) as incoming:
        members = incoming.infolist()
        require(len(members) == 5 and {m.filename for m in members} == expected
                and len({m.filename.casefold() for m in members}) == 5, 'zip_closed_member_set')
        for member in members:
            kind = stat.S_IFMT(member.external_attr >> 16)
            maximum = MAX_BINARY if member.filename.startswith('headspace-') else MAX_RECEIPT
            require(not member.is_dir() and kind in (0, stat.S_IFREG) and not member.flag_bits & 1
                and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                and 0 < member.file_size <= maximum and member.compress_size <= MAX_ARCHIVE,
                'zip_member_bounds_or_type')
        require(sum(m.file_size for m in members) <= MAX_BINARY + 4 * MAX_RECEIPT, 'zip_expanded_bounds')
        for member in members:
            destination = directory / member.filename
            with incoming.open(member) as source, destination.open('xb') as output:
                total = 0
                while True:
                    block = source.read(1024 * 1024)
                    if not block: break
                    total += len(block); require(total <= member.file_size, 'zip_actual_expanded_bounds'); output.write(block)
                require(total == member.file_size, 'zip_actual_size_mismatch')


def binary_arch(path, target):
    with path.open('rb') as stream:
        head = stream.read(64)
        if 'linux' in target:
            valid = head[:6] == b'\x7fELF\x02\x01' and int.from_bytes(head[18:20], 'little') == (183 if target.startswith('aarch64') else 62)
        elif 'apple' in target:
            valid = head[:4] == b'\xcf\xfa\xed\xfe' and int.from_bytes(head[4:8], 'little') == (0x100000c if target.startswith('aarch64') else 0x1000007)
        else:
            offset = int.from_bytes(head[60:64], 'little'); valid = head[:2] == b'MZ' and 64 <= offset <= min(1024 * 1024, path.stat().st_size - 6)
            if valid:
                stream.seek(offset); pe = stream.read(6)
                valid = pe[:4] == b'PE\0\0' and int.from_bytes(pe[4:6], 'little') == (0xaa64 if target.startswith('aarch64') else 0x8664)
    require(valid, 'input_binary_architecture')


def gui_proof(gui):
    engine = gui.get('native_engine', {})
    return (gui.get('status') == 'passed' and gui.get('working_recovery') is True
        and gui.get('portable_roundtrip') is True and engine.get('enabled') is True
        and all(type(engine.get(key, {}).get('count')) is int and engine[key]['count'] >= 3
                for key in ('draw_total_ms', 'platform_submit_ms')))


def validate_input(directory, label, source, version):
    target = TARGETS[label][2]; expected = input_names(target, version)
    require({p.name for p in directory.iterdir()} == expected, 'input_closed_set')
    for path in directory.iterdir(): require(not path.is_symlink() and path.is_file(), 'input_regular_files')
    binary = directory / next(n for n in expected if n.startswith('headspace-')); binary_arch(binary, target)
    digest = sha(binary); inventory = document(directory / f'inventory-{target}.json'); files = inventory.get('files', [])
    require(inventory.get('schema_version') == 2 and inventory.get('source_revision') == source
        and inventory.get('target') == target and inventory.get('version') == version
        and inventory.get('release_tag') == 'v' + version and inventory.get('delivery') == 'single_native_executable'
        and inventory.get('private_user_data_included') is False and len(files) == 1
        and files[0].get('path') == binary.name and files[0].get('format') == 'binary'
        and files[0].get('sha256') == digest and files[0].get('bytes') == binary.stat().st_size, 'input_inventory')
    build = document(directory / f'build-{target}.json')
    require(build.get('source_revision') == source and build.get('target') == target and build.get('runner') == label
        and build.get('status') == 'passed' and build.get('cargo_test') == 'passed' and build.get('cargo_build') == 'passed', 'input_build')
    for mode in ('audit', 'native'):
        proof = document(directory / f'verify-{"native-" if mode == "native" else ""}{target}-binary.json')
        cli = proof.get('cli', {})
        require(proof.get('source_revision') == source and proof.get('target') == target and proof.get('runner') == label
            and proof.get('mode') == mode and proof.get('audit', {}).get('sha256') == digest
            and cli.get('status') == 'passed' and cli.get('embedded_notices') == 7
            and cli.get('mcp', {}).get('status') == 'passed' and cli['mcp'].get('embedded_image_bytes') is True,
            'input_qualification')
        require(proof.get('status') == ('passed_bounded_native_checks' if mode == 'native' else 'passed_artifact_audit'), 'input_qualification_status')
        if mode == 'native': require(gui_proof(proof.get('native_gui', {})), 'input_native_gui')
    binary.chmod(0o755)
    return digest


def execute(command, phase, cwd=None, env=None, timeout=900):
    """Return bounded successful identity data; classify failures without raw logs."""
    with tempfile.TemporaryFile() as output:
        try:
            child = subprocess.Popen([str(x) for x in command], cwd=cwd, env=env, stdout=output,
                stderr=output, shell=False, start_new_session=os.name == 'posix')
        except OSError: raise BuildFailure(phase + '_unavailable', 'Required native tool unavailable') from None
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > 16 * 1024 * 1024:
                stop_child(child); raise BuildFailure(phase + '_bound', 'Native operation exceeded bounds')
            time.sleep(0.1)
        size = os.fstat(output.fileno()).st_size
        require(size <= 16 * 1024 * 1024, phase + '_output_bounds')
        if child.returncode:
            output.seek(max(0, size - 65536)); text = output.read(65536).decode(errors='replace')
            failure = BuildFailure(phase + '_failed', 'Native operation failed')
            failure.diagnostic = safe_diagnostic(text)
            raise failure
        output.seek(0)
        return output.read().decode(errors='replace').strip() if size <= 1024 * 1024 else ''


def safe_diagnostic(text):
    result = {}
    frames = re.findall(r'File "[^"\n]*[/\\](package-(?:linux|macos|windows)\.py)", line ([0-9]{1,7}), in ([A-Za-z_][A-Za-z_0-9]*)', text)
    if frames:
        file, line, function = frames[-1]
        result = dict(file=file, line=int(line))
        allowed = {'main', 'run', 'dependencies', 'tree', 'copy', 'package_one', 'validate_payload',
            'qualified_input', 'macho', 'seal_app', 'unsigned_sha', 'check_dmg', 'verifier', 'manifest',
            'source_bytes', 'revision', 'native_version', 'native_versions', 'icon_bytes', 'wxs',
            'pe_arch', 'payload_manifest', 'audit_tables', 'audit_msi', 'query', 'check',
            'summary_template', 'close', 'identity', 'winget', 'stage', 'sha', 'bounded_json'}
        if function in allowed: result['function'] = function
    codes = sorted(set(re.findall(r'\bWIX[0-9]{4}\b', text)))
    if codes: result['wix_codes'] = codes[:8]
    return result


def recipe_path(label):
    return 'scripts/package-' + {'Linux': 'linux', 'Darwin': 'macos', 'Windows': 'windows'}[TARGETS[label][0]] + '.py'


def recipe_command(recipe, incoming, candidate, label, source, version, recipe_revision, wix=None):
    command = [sys.executable, str(recipe), '--artifacts', str(incoming), '--output', str(candidate),
               '--target', TARGETS[label][2], '--source-revision', source, '--recipe-revision', recipe_revision]
    if TARGETS[label][0] == 'Windows':
        require(wix is not None, 'wix_tool_path_missing'); command.extend(['--wix', str(wix)])
    else: command.extend(['--version', version])
    return command


def output_layout(label, version):
    target = TARGETS[label][2]; system = TARGETS[label][0]
    if system == 'Linux':
        stem = f'headspace-{version}-pkg1-{target}'
        return {stem + '.deb': 'deb', stem + '.rpm': 'rpm'}, 'linux-package-inventory-r1.json', {'SHA256SUMS-linux-packages-r1'}
    if system == 'Darwin':
        return {f'headspace-{version}-pkg1-{target}.dmg': 'dmg'}, f'macos-package-inventory-{target}-r1.json', set()
    stem = f'headspace-{version}-{target}-r1'
    return {stem + '.msi': 'msi', stem + '.winget.yaml': 'winget'}, f'windows-package-inventory-{target}-r1.json', set()


def validate_outputs(candidate, label, source, version, recipe_revision, recipe_sha, input_sha):
    expected, inventory_name, sidecars = output_layout(label, version)
    require({p.name for p in candidate.iterdir()} == set(expected) | {inventory_name} | sidecars, 'output_closed_set')
    inventory_path = candidate / inventory_name; inventory = document(inventory_path)
    require(inventory.get('schema_version') == 1 and inventory.get('version') == version
        and inventory.get('source_revision') == source and inventory.get('package_revision') == 1
        and inventory.get('recipe_revision') == recipe_revision and inventory.get('recipe_sha256') == recipe_sha,
        'output_inventory_identity')
    system = TARGETS[label][0]; target = TARGETS[label][2]
    if system != 'Windows': require(inventory.get('owner_repository') == OWNER, 'output_owner')
    else: require(inventory.get('target') == target and inventory.get('input_executable_sha256') == input_sha
        and inventory.get('packaged_executable_sha256') == input_sha, 'output_windows_executable')
    rows = inventory.get('files', [])
    require(len(rows) == len(expected) and {r.get('path') for r in rows} == set(expected), 'output_inventory_members')
    outputs = []
    for row in rows:
        path = candidate / row['path']
        require(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= MAX_OUTPUT
            and row.get('format') == expected[path.name] and row.get('bytes') == path.stat().st_size
            and row.get('sha256') == sha(path), 'output_file_hash')
        if system == 'Linux':
            require(row.get('target') == target and row.get('source_revision') == source
                and row.get('executable_sha256') == input_sha and row.get('payload_audit', {}).get('status') == 'passed'
                and row['payload_audit'].get('executable_sha256') == input_sha
                and row['payload_audit'].get('executable_files') == ['usr/bin/headspace']
                and row['payload_audit'].get('symlinks') == 0, 'output_linux_payload')
        elif system == 'Darwin': validate_mac(row, inventory, label, source, input_sha)
        outputs.append(path)
    if system == 'Windows':
        audit = inventory.get('native_package_audit', {})
        require(audit.get('status') == 'passed' and audit.get('scope') == 'user'
            and audit.get('executable_count') == 1 and audit.get('custom_actions') == 0
            and audit.get('payload_audit', {}).get('status') == 'passed'
            and audit['payload_audit'].get('executable_sha256') == input_sha, 'output_windows_payload')
        manifest = document(next(path for path in outputs if path.name.endswith('.winget.yaml')))
        installer = manifest.get('Installers', [])
        msi = next(path for path in outputs if path.suffix == '.msi')
        architecture = 'arm64' if target.startswith('aarch64') else 'x64'
        require(manifest.get('PackageIdentifier') == 'Backstack.Headspace' and manifest.get('PackageVersion') == version
            and manifest.get('Scope') == 'user' and manifest.get('InstallerType') == 'wix'
            and len(installer) == 1 and installer[0].get('InstallerSha256') == sha(msi).upper()
            and installer[0].get('Architecture') == architecture
            and installer[0].get('ProductCode') == inventory.get('product_code')
            and installer[0].get('InstallerUrl') == OWNER + '/releases/download/v' + version + '/' + msi.name,
            'output_winget_identity')
    outputs.append(inventory_path)
    for name in sidecars:
        path = candidate / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= MAX_RECEIPT, 'output_sidecar_bounds')
        expected_sums = ''.join(f'{sha(p)}  {p.name}\n' for p in sorted(outputs))
        require(path.read_text() == expected_sums, 'output_checksums'); outputs.append(path)
    return outputs


def validate_mac(row, inventory, label, source, input_sha):
    proof = row.get('normalized_code_identity', {}); native = row.get('native_verification', {})
    normalized = proof.get('input_unsigned_sha256', '')
    require(inventory.get('status') == 'passed_native_macos_package_checks' and inventory.get('native_runner') == label
        and inventory.get('target') == TARGETS[label][2] and row.get('target') == TARGETS[label][2]
        and row.get('input_executable_sha256') == input_sha
        and re.fullmatch('[0-9a-f]{64}', row.get('packaged_executable_sha256', '')) is not None
        and row.get('bundle', {}).get('files', {}).get('Contents/MacOS/headspace', {}).get('sha256') == row.get('packaged_executable_sha256')
        and proof.get('status') == 'passed'
        and proof.get('method') == 'codesign_adhoc_resign_then_remove_signature_private_copies'
        and proof.get('canonical_identifier') == 'io.backstack.Headspace.normalized'
        and re.fullmatch('[0-9a-f]{64}', normalized) is not None
        and proof.get('packaged_unsigned_sha256') == normalized and row.get('normalized_code_sha256') == normalized
        and row.get('signing') == dict(kind='ad_hoc', bundle_seal_verified=True, developer_id=False, notarized=False),
        'output_mac_code_identity')
    gui = native.get('native_gui', {})
    require(all(native.get(key) == 'passed' for key in ('dmg_integrity', 'read_only_mount', 'application_bundle_layout',
        'clean_copy_install', 'version', 'removal')) and native.get('embedded_notices') == 7
        and native.get('synthetic_user_data_preserved') is True and native.get('mcp', {}).get('status') == 'passed'
        and native['mcp'].get('embedded_image_bytes') is True and gui.get('source_revision') == source
        and gui.get('target') == TARGETS[label][2] and gui.get('runner') == label
        and gui.get('status') == 'passed_bounded_native_checks'
        and gui_proof(gui.get('native_gui', {})), 'output_mac_native_proof')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', required=True, choices=TARGETS); parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--input-run-id', required=True, type=int); parser.add_argument('--source-revision', required=True)
    parser.add_argument('--recipe-revision', required=True); parser.add_argument('--version', required=True)
    parser.add_argument('--wix', type=Path); args = parser.parse_args(argv)
    report = dict(schema_version=1, owner_repository=OWNER, worker_repository=REPOSITORY,
        runner=args.runner, target=TARGETS[args.runner][2], input_run_id=args.input_run_id,
        source_revision=args.source_revision, version=args.version, recipe_revision=args.recipe_revision,
        worker_revision=os.environ.get('GITHUB_SHA', ''), cargo_invoked=False, sdk_invoked=False,
        status='failed', phase='input_identity')
    require(not args.output.is_symlink() and (not args.output.exists() or not any(args.output.iterdir())), 'output_directory')
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        source = revision(args.source_revision); recipe_revision = revision(args.recipe_revision); version = semver(args.version)
        require(0 < args.input_run_id < 10**14 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'native_hosted_repository')
        native = probe.machine_identity(); probe.validate_native(args.runner, native['os'], native['native_arch'], native['process_arch'], native['translated'])
        report['native_identity'] = native
        github = Github(os.environ.get('GH_TOKEN')); report['phase'] = 'original_run'
        worker = run_metadata(github.json(f'/actions/runs/{args.input_run_id}'), args.input_run_id, source, version)
        artifacts = artifact_set(github.json(f'/actions/runs/{args.input_run_id}/artifacts?per_page=100'), args.input_run_id, source, worker)
        report['input_worker_revision'] = worker
        env = recipe_environment(os.environ)
        with tempfile.TemporaryDirectory(prefix='headspace-native-package-', dir=os.environ['RUNNER_TEMP']) as temporary:
            work = Path(temporary); archive = work / 'input.zip'; incoming = work / 'input'
            report['phase'] = 'qualified_input'; github.archive(artifacts[args.runner]['id'], archive)
            api_digest = artifacts[args.runner].get('digest')
            if api_digest is not None:
                require(isinstance(api_digest, str) and re.fullmatch('sha256:[0-9a-f]{64}', api_digest) is not None
                    and api_digest == 'sha256:' + sha(archive), 'download_archive_digest')
            extract_archive(archive, incoming, TARGETS[args.runner][2], version)
            input_sha = validate_input(incoming, args.runner, source, version); report['input_executable_sha256'] = input_sha
            report['phase'] = 'owner_recipe'; checkout = work / 'owner-source'
            def owner_run(command, phase, **kwargs):
                kwargs['env'] = env
                return execute(command, phase, **kwargs)
            fetch_source(checkout, recipe_revision, execute=owner_run)
            git = ['git', '-c', 'credential.helper=', '-c', 'core.askPass=', '-c', 'credential.interactive=false']
            execute(git + ['fetch', '--depth=1', 'origin', source], 'app_source_fetch', cwd=checkout, env=env, timeout=120)
            actual = execute(git + ['rev-parse', source + '^{commit}'], 'app_source_identity', cwd=checkout, env=env, timeout=30)
            require(actual == source, 'app_source_revision')
            cargo = execute(git + ['show', source + ':Cargo.toml'], 'app_source_version', cwd=checkout, env=env, timeout=30)
            require(tomllib.loads(cargo)['workspace']['package']['version'] == version, 'app_source_version')
            path = checkout / recipe_path(args.runner)
            require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 256 * 1024, 'recipe_file')
            recipe_sha = sha(path); report.update(recipe=recipe_path(args.runner), recipe_sha256=recipe_sha)
            candidate = work / 'candidate'; report['phase'] = 'package_and_verify'
            execute(recipe_command(path, incoming, candidate, args.runner, source, version, recipe_revision, args.wix),
                    'owner_recipe', cwd=checkout, env=env, timeout=900)
            report['phase'] = 'output_audit'
            outputs = validate_outputs(candidate, args.runner, source, version, recipe_revision, recipe_sha, input_sha)
            require(validate_input(incoming, args.runner, source, version) == input_sha, 'original_executable_changed')
            for path in outputs: shutil.copyfile(path, args.output / path.name)
            report.update(status='passed', phase='completed', files=[dict(path=p.name, bytes=p.stat().st_size, sha256=sha(p)) for p in outputs],
                qualification='source_owned_receipts_preserved_no_inferred_install_or_signing_pass')
    except (BuildFailure, probe.ProbeError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
        # Failure receipts contain fixed labels/source coordinates, never messages,
        # URLs, download tokens, command text, source, environment or raw logs.
        report['failure_code'] = error.code if isinstance(error, BuildFailure) else 'native_packaging_boundary_failed'
        if isinstance(error, BuildFailure) and hasattr(error, 'diagnostic'): report['owner_recipe_diagnostic'] = error.diagnostic
    receipt = args.output / f'build-native-package-{TARGETS[args.runner][2]}.json'
    encoded = json.dumps(report, indent=2) + '\n'; require(len(encoded.encode()) <= MAX_RECEIPT, 'worker_receipt_bounds')
    receipt.write_text(encoded, encoding='utf-8')
    print(json.dumps(dict(status=report['status'], target=report['target'], phase=report['phase'])))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__': raise SystemExit(main())
