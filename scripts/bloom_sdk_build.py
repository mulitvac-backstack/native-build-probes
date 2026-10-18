#!/usr/bin/env python3
"""Compute Bloom-owned native SDK releases; never fetch an application recipe."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import probe
from bloom_profile import read_pin, extract_profile, private_env, revision, semver, ALLOWED_ENV
from bloom_native import run_driver, NativeFailure
from sdk_artifacts import collect_sdk, make_envelope, ArtifactError, native_executable_arch

REPOSITORY = 'mulitvac-backstack/native-build-probes'


def build(args):
    source_revision, version = revision(args.revision), semver(args.version)
    system, arch, target = probe.TARGETS[args.runner]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    result = dict(schema_version=1, target=target, sdk_version=version, recipe_revision=source_revision,
                  source_repository='backstack.io/bloomdb', status='failed', phase='native_identity')
    try:
        native = probe.machine_identity()
        probe.validate_native(args.runner, native['os'], native['native_arch'], native['process_arch'], native['translated'])
        result['phase'] = 'profile_pin'
        pin = read_pin(args.profile, source_revision, version, os.environ.get('BLOOM_SDK_SHA256', ''))
        sha = pin['archive_sha256']
        result['source_input_sha256'] = sha
        with tempfile.TemporaryDirectory(prefix='bloom-private-sdk-') as directory:
            directory = Path(directory)
            result['phase'] = 'profile_extract'
            profile = extract_profile(args.sdk_file, pin, directory / 'profile')
            sdk_source = profile / 'input/bloomdb'
            sdk_output = directory / 'built-sdk'
            env_json = directory / 'env.json'
            env = private_env(probe.windows_compiler_env(arch) if system == 'Windows' else os.environ.copy())
            producer = dict(repository=REPOSITORY, workflow='bloom-sdk.yml', run_id=int(os.environ.get('GITHUB_RUN_ID', '0')),
                            head_sha=os.environ.get('GITHUB_SHA', ''), recipe_repository='backstack.io/bloomdb',
                            recipe_revision=source_revision, profile_path='sdk/embedded/sdk-profile.json')
            if producer['run_id'] <= 0 or re.fullmatch('[0-9a-f]{40}', producer['head_sha']) is None:
                raise ArtifactError('Bloom SDK compute identity must be immutable')
            result['producer'] = producer
            failure_identity = dict(source_input_sha256=sha, recipe_revision=source_revision,
                                    app_source_revision=source_revision, target=target, version=version,
                                    sdk_version=version, run_id=producer['run_id'], worker_sha=producer['head_sha'], phase='sdk_build')
            result['phase'] = 'sdk_native_build_and_tests'
            run_driver([sys.executable, str(profile / 'recipe/build_bloom.py'), '--source', str(sdk_source),
                        '--output', str(sdk_output), '--env-json', str(env_json), '--target', target],
                       profile, sdk_output, env, output, failure_identity)
            link = json.loads(env_json.read_text())
            if not isinstance(link, dict) or not link or set(link) - ALLOWED_ENV or any(not isinstance(v, str) for v in link.values()):
                raise ArtifactError('Bloom SDK link environment is not allowlisted')
            suffix = '.exe' if system == 'Windows' else ''
            candidates = [sdk_output / 'build' / ('bloom-sdk-smoke' + suffix), sdk_output / 'build/Release' / ('bloom-sdk-smoke' + suffix)]
            smoke = next((p for p in candidates if p.is_file() and not p.is_symlink()), None)
            if smoke is None:
                raise ArtifactError('Bloom native semantic executable is missing')
            native_executable_arch(smoke, target)
            result['phase'] = 'sdk_encrypt'
            files = collect_sdk(profile, sdk_source, sdk_output, link, notices_directory=profile / 'notices')
            identity = dict(sdk_version=version, source_input_sha256=sha, target=target, producer=producer,
                            private_source_revision=source_revision, private_source_subdirectory='sdk/embedded/input/bloomdb',
                            abi=dict(os=system, arch=arch, pointer_width=64, endianness='little'),
                            capability_profile=pin['capability_profile'], binding_package_version=pin['binding_package_version'])
            ciphertext, manifest = make_envelope(files, identity)
            stem = 'bloom-sdk-' + version + '-' + target
            (output / (stem + '.aesgcm')).write_bytes(ciphertext)
            (output / (stem + '.manifest.json')).write_bytes(manifest)
            result.update(status='passed', phase='completed', tests={'native_build': 'passed', 'required_sdk_semantics': 'passed'},
                          artifact_name=stem, private_source_revision=source_revision,
                          private_source_subdirectory='sdk/embedded/input/bloomdb')
    except NativeFailure as exc:
        result['blocker'] = dict(code=exc.code, message=str(exc))
        if exc.report is not None:
            result['sdk_diagnostics'] = exc.report
        if exc.encrypted_log is not None:
            result['encrypted_failure_log'] = exc.encrypted_log
    except (ArtifactError, OSError, ValueError, RuntimeError, probe.ProbeError):
        result['blocker'] = dict(code='bloom_sdk_producer_failed', message='Bloom SDK producer failed during ' + result['phase'])
    (output / ('bloom-build-' + target + '.json')).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner', choices=probe.TARGETS, required=True)
    parser.add_argument('--revision', required=True, help='Exact private Bloom source/recipe revision')
    parser.add_argument('--version', required=True)
    parser.add_argument('--profile', type=Path, default=Path(__file__).resolve().parents[1] / 'profiles/bloom-sdk-input.json')
    parser.add_argument('--sdk-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    return build(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
