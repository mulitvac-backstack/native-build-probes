"""Offline trust/packaging boundaries; fixtures do not qualify native installers."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import zipfile

SPEC = importlib.util.spec_from_file_location('native_packaging', Path(__file__).resolve().parent / 'scripts/headspace_native_packaging.py')
r = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(r)
SOURCE = 'a' * 40
RECIPE = 'b' * 40
WORKER = 'c' * 40
VERSION = '0.1.0-alpha.2'
RUN = 123456


def metadata():
    return dict(id=RUN, status='completed', conclusion='success', event='workflow_dispatch', path=r.WORKFLOW,
        display_title=f'Headspace {VERSION} @ {SOURCE}', head_sha=WORKER,
        repository=dict(full_name=r.REPOSITORY, private=False))


def artifacts():
    return dict(total_count=6, artifacts=[dict(id=index + 1, name=f'headspace-{label}-{SOURCE}', expired=False,
        size_in_bytes=100, workflow_run=dict(id=RUN, head_sha=WORKER)) for index, label in enumerate(r.TARGETS)])


def header(target):
    data = bytearray(70)
    if 'linux' in target:
        data[:6] = b'\x7fELF\x02\x01'; data[18:20] = (183 if target.startswith('aarch64') else 62).to_bytes(2, 'little')
    elif 'apple' in target:
        data[:4] = b'\xcf\xfa\xed\xfe'; data[4:8] = (0x100000c if target.startswith('aarch64') else 0x1000007).to_bytes(4, 'little')
    else:
        data[:2] = b'MZ'; data[60:64] = (64).to_bytes(4, 'little'); data[64:68] = b'PE\0\0'
        data[68:70] = (0xaa64 if target.startswith('aarch64') else 0x8664).to_bytes(2, 'little')
    return data


def input_fixture(directory, label):
    directory.mkdir(); target = r.TARGETS[label][2]
    name = next(n for n in r.input_names(target, VERSION) if n.startswith('headspace-'))
    binary = directory / name; binary.write_bytes(header(target)); digest = r.sha(binary)
    (directory / f'inventory-{target}.json').write_text(json.dumps(dict(schema_version=2,
        source_revision=SOURCE, version=VERSION, target=target, release_tag='v' + VERSION,
        delivery='single_native_executable', private_user_data_included=False,
        files=[dict(path=name, format='binary', bytes=binary.stat().st_size, sha256=digest)])))
    (directory / f'build-{target}.json').write_text(json.dumps(dict(source_revision=SOURCE, target=target,
        runner=label, status='passed', cargo_test='passed', cargo_build='passed')))
    for mode in ('audit', 'native'):
        doc = dict(source_revision=SOURCE, target=target, runner=label, mode=mode,
            audit=dict(sha256=digest), status='passed_artifact_audit', cli=dict(status='passed', embedded_notices=7,
            mcp=dict(status='passed', embedded_image_bytes=True)))
        if mode == 'native':
            doc.update(status='passed_bounded_native_checks', native_gui=dict(status='passed', working_recovery=True,
                portable_roundtrip=True, native_engine=dict(enabled=True, draw_total_ms=dict(count=3), platform_submit_ms=dict(count=3))))
        (directory / f'verify-{"native-" if mode == "native" else ""}{target}-binary.json').write_text(json.dumps(doc))
    return binary, digest


def linux_output(directory, label='ubuntu-24.04'):
    directory.mkdir(); expected, name, _ = r.output_layout(label, VERSION); target = r.TARGETS[label][2]
    rows = []
    for file, fmt in expected.items():
        path = directory / file; path.write_bytes(b'package fixture ' + fmt.encode())
        rows.append(dict(path=file, format=fmt, bytes=path.stat().st_size, sha256=r.sha(path),
            target=target, source_revision=SOURCE, executable_sha256='d'*64,
            payload_audit=dict(status='passed', executable_sha256='d'*64, executable_files=['usr/bin/headspace'], symlinks=0)))
    doc = dict(schema_version=1, owner_repository=r.OWNER, source_revision=SOURCE, version=VERSION,
        recipe_revision=RECIPE, recipe_sha256='e'*64, package_revision=1, files=rows)
    (directory / name).write_text(json.dumps(doc))
    paths = sorted(p for p in directory.iterdir())
    (directory / 'SHA256SUMS-linux-packages-r1').write_text(''.join(f'{r.sha(p)}  {p.name}\n' for p in paths))
    return name


class NativePackagingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup); self.root = Path(temp.name)

    def test_run_source_version_workflow_and_repository_are_independently_bound(self):
        self.assertEqual(r.run_metadata(metadata(), RUN, SOURCE, VERSION), WORKER)
        for key, value in [('id', 12), ('status', 'in_progress'), ('conclusion', 'failure'), ('event', 'pull_request'),
                           ('path', '.github/workflows/other.yml'), ('display_title', 'Headspace wrong'), ('head_sha', 'main')]:
            doc = metadata(); doc[key] = value
            self.assertRaises(r.BuildFailure, r.run_metadata, doc, RUN, SOURCE, VERSION)
        doc = metadata(); doc['repository']['full_name'] = 'elsewhere/repo'
        self.assertRaises(r.BuildFailure, r.run_metadata, doc, RUN, SOURCE, VERSION)

    def test_all_six_exact_artifact_names_and_native_run_provenance_required(self):
        self.assertEqual(set(r.artifact_set(artifacts(), RUN, SOURCE, WORKER)), set(r.TARGETS))
        for mutate in [lambda d: d['artifacts'].pop(), lambda d: d['artifacts'][0].update(expired=True),
                       lambda d: d['artifacts'][0].update(name='other'),
                       lambda d: d['artifacts'][0]['workflow_run'].update(head_sha='d'*40),
                       lambda d: d['artifacts'][0].update(size_in_bytes=r.MAX_ARCHIVE+1),
                       lambda d: d['artifacts'][0].update(id=d['artifacts'][1]['id'])]:
            doc = artifacts(); mutate(doc); self.assertRaises(r.BuildFailure, r.artifact_set, doc, RUN, SOURCE, WORKER)

    def test_blob_redirect_only_accepts_expected_https_hosts_without_credentials(self):
        r.validate_blob_url('https://production.blob.core.windows.net/a?sig=opaque')
        r.validate_blob_url('https://results.actions.githubusercontent.com/a')
        for url in ['http://production.blob.core.windows.net/a', 'https://evil.invalid/a',
                    'https://production.blob.core.windows.net.evil.invalid/a',
                    'https://token@production.blob.core.windows.net/a', 'https://production.blob.core.windows.net:8443/a']:
            self.assertRaises(r.BuildFailure, r.validate_blob_url, url)

    def test_github_token_is_not_forwarded_to_artifact_redirect(self):
        class Response(io.BytesIO):
            headers = {}
        class Opener:
            def __init__(self): self.requests = []
            def open(self, request, timeout):
                self.requests.append(request)
                if len(self.requests) == 1:
                    raise urllib.error.HTTPError(request.full_url, 302, 'redirect', {'Location': 'https://prod.blob.core.windows.net/a?sig=opaque'}, None)
                return Response(b'zipfixture')
        api = r.Github('sensitive-token'); api.opener = Opener(); api.archive(1, self.root / 'download')
        self.assertEqual(api.opener.requests[0].get_header('Authorization'), 'Bearer sensitive-token')
        self.assertIsNone(api.opener.requests[1].get_header('Authorization'))

    def archive(self, mutate=None):
        source = self.root / 'fixture'; input_fixture(source, 'ubuntu-24.04')
        path = self.root / 'archive.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as output:
            for index, member in enumerate(source.iterdir()):
                name = member.name; data = member.read_bytes(); entry = zipfile.ZipInfo(name)
                if mutate and index == 0: mutate(entry)
                output.writestr(entry, data)
        return path

    def test_zip_closed_set_extracts_exact_native_input_bytes(self):
        archive = self.archive(); destination = self.root / 'extracted'; target = r.TARGETS['ubuntu-24.04'][2]
        r.extract_archive(archive, destination, target, VERSION)
        self.assertEqual(r.validate_input(destination, 'ubuntu-24.04', SOURCE, VERSION), r.sha(next(destination.glob('headspace-*'))))

    def test_zip_traversal_symlinks_duplicates_and_oversize_rejected_before_writes(self):
        mutations = [lambda e: setattr(e, 'filename', '../outside'),
                     lambda e: setattr(e, 'external_attr', (stat.S_IFLNK | 0o777) << 16)]
        for index, mutate in enumerate(mutations):
            with tempfile.TemporaryDirectory() as temp:
                original = self.root; self.root = Path(temp)
                try:
                    archive = self.archive(mutate); destination = self.root / 'extracted'
                    self.assertRaises(r.BuildFailure, r.extract_archive, archive, destination, r.TARGETS['ubuntu-24.04'][2], VERSION)
                    self.assertEqual(list(destination.iterdir()), [])
                finally: self.root = original
        archive = self.archive(); destination = self.root / 'small-bound'
        with patch.object(r, 'MAX_BINARY', 2), patch.object(r, 'MAX_RECEIPT', 2):
            self.assertRaises(r.BuildFailure, r.extract_archive, archive, destination, r.TARGETS['ubuntu-24.04'][2], VERSION)
        self.assertEqual(list(destination.iterdir()), [])

    def test_each_native_input_machine_and_exact_hash_are_required(self):
        for label in r.TARGETS:
            binary, digest = input_fixture(self.root / label, label)
            self.assertEqual(r.validate_input(binary.parent, label, SOURCE, VERSION), digest)
            binary.write_bytes(binary.read_bytes() + b'changed')
            self.assertRaises(r.BuildFailure, r.validate_input, binary.parent, label, SOURCE, VERSION)

    def test_input_native_gui_and_cli_resource_evidence_cannot_be_omitted(self):
        label = 'windows-11-arm'; binary, _ = input_fixture(self.root / 'input', label); target = r.TARGETS[label][2]
        path = binary.parent / f'verify-native-{target}-binary.json'; doc = json.loads(path.read_text())
        doc['native_gui']['portable_roundtrip'] = False; path.write_text(json.dumps(doc))
        self.assertRaises(r.BuildFailure, r.validate_input, binary.parent, label, SOURCE, VERSION)

    def test_recipe_environment_removes_tokens_git_overrides_and_provider_secrets(self):
        env = r.recipe_environment(dict(PATH='/tools', RUNNER_TEMP='/owned', GH_TOKEN='secret', GITHUB_TOKEN='secret',
            BLOOM_ARTIFACT_KEY='secret', OPENAI_API_KEY='secret', AWS_SECRET_ACCESS_KEY='secret',
            ACTIONS_RUNTIME_TOKEN='secret', GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0='http.extraheader',
            GIT_CONFIG_VALUE_0='secret', GIT_SSH_COMMAND='sensitive', LD_PRELOAD='sensitive'))
        self.assertEqual(set(env), {'PATH', 'RUNNER_TEMP', 'GIT_TERMINAL_PROMPT', 'GCM_INTERACTIVE', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL'})
        self.assertNotIn('secret', env.values())

    def test_recipe_commands_are_closed_platform_specific_packaging_only(self):
        for label in r.TARGETS:
            command = r.recipe_command('recipe.py', 'input', 'output', label, SOURCE, VERSION, RECIPE, wix='wix.exe')
            self.assertNotIn('cargo', command); self.assertNotIn('build', command)
            self.assertEqual('--version' in command, r.TARGETS[label][0] != 'Windows')
            self.assertEqual('--wix' in command, r.TARGETS[label][0] == 'Windows')
            self.assertIn(SOURCE, command); self.assertIn(RECIPE, command)
        self.assertRaises(r.BuildFailure, r.recipe_command, 'recipe.py', 'input', 'output', 'windows-2025', SOURCE, VERSION, RECIPE)

    def test_outputs_need_exact_installer_set_hashes_and_original_executable_identity(self):
        directory = self.root / 'packages'; inventory = linux_output(directory)
        result = r.validate_outputs(directory, 'ubuntu-24.04', SOURCE, VERSION, RECIPE, 'e'*64, 'd'*64)
        self.assertEqual(len(result), 4)
        next(directory.glob('*.deb')).write_bytes(b'tampered')
        self.assertRaises(r.BuildFailure, r.validate_outputs, directory, 'ubuntu-24.04', SOURCE, VERSION, RECIPE, 'e'*64, 'd'*64)

    def test_output_recipe_source_hash_and_no_executable_forwarding_are_enforced(self):
        directory = self.root / 'packages'; linux_output(directory)
        for source, recipe in [('f'*40, RECIPE), (SOURCE, 'f'*40)]:
            self.assertRaises(r.BuildFailure, r.validate_outputs, directory, 'ubuntu-24.04', source, VERSION, recipe, 'e'*64, 'd'*64)
        (directory / 'headspace.exe').write_bytes(b'extra')
        self.assertRaises(r.BuildFailure, r.validate_outputs, directory, 'ubuntu-24.04', SOURCE, VERSION, RECIPE, 'e'*64, 'd'*64)

    def test_mac_bundle_must_prove_signed_code_derivation_and_fresh_native_journey(self):
        label = 'macos-15'; target = r.TARGETS[label][2]; directory = self.root / 'mac'; directory.mkdir()
        expected, inventory_name, _ = r.output_layout(label, VERSION); filename = next(iter(expected))
        path = directory / filename; path.write_bytes(b'dmgfixture')
        gui = dict(status='passed', working_recovery=True, portable_roundtrip=True,
            native_engine=dict(enabled=True, draw_total_ms=dict(count=3), platform_submit_ms=dict(count=3)))
        native = {key: 'passed' for key in ('dmg_integrity', 'read_only_mount', 'application_bundle_layout', 'clean_copy_install', 'version', 'removal')}
        native.update(embedded_notices=7, synthetic_user_data_preserved=True, mcp=dict(status='passed', embedded_image_bytes=True),
            native_gui=dict(source_revision=SOURCE, target=target, runner=label, status='passed_bounded_native_checks', native_gui=gui))
        row = dict(path=filename, format='dmg', bytes=path.stat().st_size, sha256=r.sha(path), target=target,
            input_executable_sha256='d'*64, packaged_executable_sha256='f'*64, normalized_code_sha256='1'*64,
            normalized_code_identity=dict(status='passed', method='codesign_adhoc_resign_then_remove_signature_private_copies',
                canonical_identifier='io.backstack.Headspace.normalized', input_unsigned_sha256='1'*64, packaged_unsigned_sha256='1'*64),
            signing=dict(kind='ad_hoc', bundle_seal_verified=True, developer_id=False, notarized=False),
            bundle=dict(files={'Contents/MacOS/headspace': dict(sha256='f'*64)}), native_verification=native)
        doc = dict(schema_version=1, owner_repository=r.OWNER, version=VERSION, source_revision=SOURCE, target=target,
            recipe_revision=RECIPE, recipe_sha256='e'*64, package_revision=1, native_runner=label,
            status='passed_native_macos_package_checks', files=[row])
        inventory = directory / inventory_name; inventory.write_text(json.dumps(doc))
        self.assertEqual(len(r.validate_outputs(directory, label, SOURCE, VERSION, RECIPE, 'e'*64, 'd'*64)), 2)
        for mutate in [lambda d: d['files'][0]['normalized_code_identity'].update(packaged_unsigned_sha256='2'*64),
                       lambda d: d['files'][0]['native_verification']['native_gui']['native_gui'].update(working_recovery=False),
                       lambda d: d['files'][0]['bundle']['files']['Contents/MacOS/headspace'].update(sha256='d'*64)]:
            changed = copy.deepcopy(doc); mutate(changed); inventory.write_text(json.dumps(changed))
            self.assertRaises(r.BuildFailure, r.validate_outputs, directory, label, SOURCE, VERSION, RECIPE, 'e'*64, 'd'*64)

    def test_windows_installer_manifest_hash_scope_and_native_architecture_must_agree(self):
        label = 'windows-11-arm'; target = r.TARGETS[label][2]; directory = self.root / 'win'; directory.mkdir()
        expected, inventory_name, _ = r.output_layout(label, VERSION)
        msi_name = next(n for n in expected if n.endswith('.msi')); manifest_name = next(n for n in expected if n.endswith('.yaml'))
        msi = directory / msi_name; msi.write_bytes(b'msifixture')
        manifest = dict(PackageIdentifier='Backstack.Headspace', PackageVersion=VERSION, Scope='user', InstallerType='wix',
            Installers=[dict(Architecture='arm64', ProductCode='{PRODUCT}', InstallerSha256=r.sha(msi).upper(),
                InstallerUrl=r.OWNER + '/releases/download/v' + VERSION + '/' + msi_name)])
        (directory / manifest_name).write_text(json.dumps(manifest))
        doc = dict(schema_version=1, version=VERSION, source_revision=SOURCE, target=target, package_revision=1,
            recipe_revision=RECIPE, recipe_sha256='e'*64, input_executable_sha256='d'*64,
            packaged_executable_sha256='d'*64, product_code='{PRODUCT}', native_package_audit=dict(status='passed',
                scope='user', executable_count=1, custom_actions=0, payload_audit=dict(status='passed', executable_sha256='d'*64)),
            files=[dict(path=n, format=fmt, bytes=(directory/n).stat().st_size, sha256=r.sha(directory/n)) for n,fmt in expected.items()])
        inventory = directory / inventory_name; inventory.write_text(json.dumps(doc))
        self.assertEqual(len(r.validate_outputs(directory, label, SOURCE, VERSION, RECIPE, 'e'*64, 'd'*64)), 3)
        manifest['Installers'][0]['Architecture'] = 'x64'; (directory / manifest_name).write_text(json.dumps(manifest))
        row = next(row for row in doc['files'] if row['format'] == 'winget')
        row.update(bytes=(directory/manifest_name).stat().st_size, sha256=r.sha(directory/manifest_name))
        inventory.write_text(json.dumps(doc))
        self.assertRaises(r.BuildFailure, r.validate_outputs, directory, label, SOURCE, VERSION, RECIPE, 'e'*64, 'd'*64)

    def test_receipt_and_version_bounds_and_safe_failure_diagnostics(self):
        for value in ['v0.1.0', '0.1.0-alpha.01', '0.1', '1.0.0;echo secret']:
            self.assertRaises(r.BuildFailure, r.semver, value)
        self.assertEqual(r.semver(VERSION), VERSION)
        self.assertEqual(r.safe_diagnostic('secret token\n File "/private/source/scripts/package-windows.py", line 22, in main\nWIX0100 secret'),
            dict(file='package-windows.py', line=22, function='main', wix_codes=['WIX0100']))
        path = self.root / 'oversized.json'; path.write_bytes(b' ' * (r.MAX_RECEIPT + 1))
        self.assertRaises(r.BuildFailure, r.document, path)

    def test_workflow_uses_only_fixed_native_runners_readonly_permissions_and_package_paths(self):
        workflow = (Path(__file__).resolve().parent / '.github/workflows/headspace-native-packages.yml').read_text()
        for label in r.TARGETS: self.assertIn(label, workflow)
        self.assertIn('actions: read', workflow); self.assertIn('contents: read', workflow)
        self.assertNotIn('secrets.', workflow); self.assertNotIn('cargo ', workflow); self.assertNotIn('cache', workflow)
        self.assertIn('dotnet tool install wix --version 5.0.2 --tool-path', workflow)
        self.assertNotIn('headspace-native-packages/headspace-*', workflow)


if __name__ == '__main__': unittest.main()
