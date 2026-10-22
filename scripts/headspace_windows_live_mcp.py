#!/usr/bin/env python3
"""Diagnostic-only Windows check of owner-published, hash-pinned alpha.3 bytes."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe
from headspace_source_build import BuildFailure, fetch_source
from headspace_native_packaging import binary_arch, execute, recipe_environment, sha, NoRedirect

OWNER = 'https://git.multivac.network/backstack.io/headspace'
APPLICATION_SOURCE = 'fd9fa7b5aea3d513db215f882aa9de1bdc0e751d'
APPLICATION_RUN = 39318900665
VERSION = '0.1.0-alpha.3'
RUNNERS = ('windows-2025', 'windows-11-arm')
MAX_BINARY = 128 * 1024 * 1024
MAX_RECEIPT = 64 * 1024


def require(value, code):
    if not value:
        raise BuildFailure(code, 'Diagnostic boundary rejected input or output')


def public_download(path, row):
    require(set(row) == {'name', 'bytes', 'sha256'}, 'binary_record_fields')
    require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_BINARY, 'binary_size_record')
    require(re.fullmatch('[0-9a-f]{64}', row['sha256']), 'binary_digest_record')
    url = OWNER + '/releases/download/v' + VERSION + '/' + row['name']
    request = urllib.request.Request(url, headers={'User-Agent': 'git/2.43.0'})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as incoming, path.open('xb') as output:
        require(incoming.status == 200 and incoming.url == url, 'owner_download_identity')
        count = 0
        while block := incoming.read(1024 * 1024):
            count += len(block)
            require(count <= row['bytes'], 'owner_download_bound')
            output.write(block)
    require(path.stat().st_size == row['bytes'] and sha(path) == row['sha256'], 'owner_download_bytes')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', required=True, choices=RUNNERS)
    parser.add_argument('--qa-revision', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    report = dict(schema_version=1, status='failed', phase='identity', runner=args.runner,
        qa_source_revision=args.qa_revision, application_source_revision=APPLICATION_SOURCE,
        application_run_id=APPLICATION_RUN, version=VERSION, source_repository=OWNER,
        cargo_invoked=False, sdk_invoked=False, installers_invoked=False)
    try:
        require(re.fullmatch('[0-9a-f]{40}', args.qa_revision), 'invalid_qa_revision')
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('GITHUB_REPOSITORY') == 'mulitvac-backstack/native-build-probes', 'hosted_runner_required')
        identity = probe.machine_identity()
        probe.validate_native(args.runner, identity['os'], identity['native_arch'], identity['process_arch'], identity['translated'])
        report['native_identity'] = identity
        env = recipe_environment(os.environ)
        with tempfile.TemporaryDirectory(prefix='headspace-live-adapter-', dir=os.environ['RUNNER_TEMP']) as temporary:
            root = Path(temporary)
            checkout = root / 'owner-source'
            report['phase'] = 'source_fetch'
            def owner_run(command, phase, **kwargs):
                kwargs['env'] = env
                return execute(command, phase, **kwargs)
            fetch_source(checkout, args.qa_revision, execute=owner_run)
            contract_file = checkout / 'docs/release/alpha3-publication-contract.json'
            require(not contract_file.is_symlink() and contract_file.is_file() and contract_file.stat().st_size <= 1024 * 1024, 'contract_file')
            contract = json.loads(contract_file.read_text(encoding='utf-8'))
            require(contract['owner_repository'] == OWNER and contract['source'] == dict(repository=OWNER, revision=APPLICATION_SOURCE)
                and contract['version']['value'] == VERSION and contract['release']['tag'] == 'v' + VERSION
                and contract['compute']['application_run_id'] == APPLICATION_RUN, 'published_contract_identity')
            target = probe.TARGETS[args.runner][2]
            name = f'headspace-{VERSION}-{target}.exe'
            matches = [row for row in contract['assets'] if row.get('name') == name]
            require(len(matches) == 1, 'published_binary_record')
            row = matches[0]
            binary = root / name
            report['phase'] = 'published_binary_download'
            public_download(binary, row)
            binary_arch(binary, target)
            report['binary_sha256'] = row['sha256']
            fixture = checkout / 'experiments/windows-live-mcp/probe.py'
            require(not fixture.is_symlink() and fixture.is_file() and fixture.stat().st_size <= MAX_RECEIPT
                and fixture.resolve().is_relative_to(checkout.resolve()), 'owner_fixture_file')
            report['fixture_sha256'] = sha(fixture)
            proof = root / 'native-live-mcp.json'
            command = [sys.executable, str(fixture), '--binary', str(binary), '--binary-sha256', row['sha256'],
                '--source-revision', APPLICATION_SOURCE, '--report', str(proof)]
            report['phase'] = 'native_live_mcp'
            try:
                execute(command, 'native_live_mcp', cwd=root, env=env, timeout=120)
            except BuildFailure as error:
                report['failure_code'] = error.code
            require(proof.is_file() and not proof.is_symlink() and proof.stat().st_size <= MAX_RECEIPT, 'native_receipt_missing')
            value = json.loads(proof.read_text(encoding='utf-8'))
            require(value.get('source_revision') == APPLICATION_SOURCE and value.get('binary_sha256') == row['sha256']
                and value.get('project_argument_supplied') is False and value.get('user_data_accessed') is False, 'native_receipt_identity')
            report['native_probe'] = value
            report.update(status='passed_existing_release_live_mcp' if value.get('status') == 'passed_gui_live_mcp_attachment' else 'failed', phase='complete')
    except Exception as error:
        report['failure_code'] = error.code if isinstance(error, BuildFailure) else type(error).__name__
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    require(len(encoded.encode()) <= MAX_RECEIPT, 'aggregate_receipt_bound')
    (args.output / 'windows-live-mcp.json').write_text(encoded, encoding='utf-8')
    print(json.dumps(dict(status=report['status'], runner=args.runner, phase=report['phase'], failure_code=report.get('failure_code'))))
    return 0 if report['status'] == 'passed_existing_release_live_mcp' else 1


if __name__ == '__main__':
    raise SystemExit(main())
