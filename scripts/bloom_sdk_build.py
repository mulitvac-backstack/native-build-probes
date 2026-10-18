#!/usr/bin/env python3
"""Produce encrypted, natively tested Bloom SDKs from one owner-pinned input."""
import argparse
import json
import importlib.util
import re
import os
from pathlib import Path
import sys
import tempfile

from headspace_release_build import (BuildFailure,SdkFailure,probe,fetch_source,validate_revision,
    validate_version,pinned_sdk_sha,extract_sdk,run_sdk,ALLOWED_ENV,hosted_failure_identity)
from sdk_artifacts import collect_sdk,make_envelope,ArtifactError

REPOSITORY='mulitvac-backstack/native-build-probes'


def build(args):
    revision=validate_revision(args.revision);version=validate_version(args.version)
    system,arch,target=probe.TARGETS[args.runner]
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    result=dict(schema_version=1,target=target,sdk_version=version,recipe_revision=revision,status='failed',phase='native_identity')
    try:
        identity=probe.machine_identity();probe.validate_native(args.runner,identity['os'],identity['native_arch'],identity['process_arch'],identity['translated'])
        with tempfile.TemporaryDirectory(prefix='bloom-private-sdk-')as directory:
            source=Path(directory)/'source';result['phase']='source_fetch';fetch_source(source,revision)
            pin=json.loads((source/'docs/release/bloom-sdk-input.json').read_text())
            if pin.get('sdk_version')!=version:raise BuildFailure('sdk_version_mismatch','SDK version differs from immutable input manifest')
            sha=pinned_sdk_sha(source,os.environ.get('BLOOM_SDK_SHA256',''));result['source_input_sha256']=sha
            result['phase']='sdk_extract';sdk=extract_sdk(args.sdk_file,sha,source/'.private')
            env=probe.windows_compiler_env(arch)if system=='Windows'else os.environ.copy()
            for key in list(env):
                if key.startswith('BLOOM_SDK_')or key in ('BLOOM_ARTIFACT_KEY','GH_TOKEN','GITHUB_TOKEN'):env.pop(key)
            sdk_output=source/'.private/bloom-sdk';env_json=Path(directory)/'env.json';result['phase']='sdk_native_build_and_tests'
            run_sdk([sys.executable,str(source/'scripts/ci/build_bloom.py'),'--source',str(sdk),'--output',str(sdk_output),'--env-json',str(env_json),'--target',target],source,env,failure_output=output,failure_identity=hosted_failure_identity(source,target,version,revision,'sdk_build'))
            link=json.loads(env_json.read_text())
            if set(link)-ALLOWED_ENV:raise BuildFailure('sdk_link_contract','Native SDK link environment is not allowlisted')
            result['phase']='sdk_encrypt'
            producer=dict(repository=REPOSITORY,workflow='bloom-sdk.yml',run_id=int(os.environ.get('GITHUB_RUN_ID','0')),head_sha=os.environ.get('GITHUB_SHA',''),recipe_revision=revision)
            if producer['run_id']<=0 or re.fullmatch('[0-9a-f]{40}',producer['head_sha'])is None:raise BuildFailure('sdk_producer_identity','SDK artifacts require immutable hosted producer identity')
            # CTest execution on ARM must not qualify an emulated x64 binary.
            suffix='.exe'if system=='Windows'else''
            candidates=[sdk_output/'build'/('headspace-sdk-smoke'+suffix),sdk_output/'build/Release'/('headspace-sdk-smoke'+suffix)]
            smoke=next((p for p in candidates if p.is_file()),None)
            if smoke is None:raise BuildFailure('sdk_native_binary','Native SDK semantic executable missing')
            spec=importlib.util.spec_from_file_location('headspace_package_native_identity',source/'scripts/package.py')
            package=importlib.util.module_from_spec(spec);spec.loader.exec_module(package)
            try:package.binary_arch(smoke,target)
            except Exception:raise BuildFailure('sdk_native_architecture','SDK semantic executable architecture differs from native target')from None
            files=collect_sdk(source,sdk,sdk_output,link)
            identity=dict(sdk_version=version,source_input_sha256=sha,target=target,producer=producer,private_source_revision=pin.get('private_source_revision'),private_source_subdirectory=pin.get('private_source_subdirectory'),
                abi=dict(os=system,arch=arch,pointer_width=64,endianness='little'),
                capability_profile=pin.get('capability_profile'),binding_package_version=pin.get('binding_package_version'))
            ciphertext,manifest=make_envelope(files,identity)
            stem='bloom-sdk-'+version+'-'+target
            (output/(stem+'.aesgcm')).write_bytes(ciphertext)
            (output/(stem+'.manifest.json')).write_bytes(manifest)
            result.update(status='passed',phase='completed',tests={'native_build':'passed','required_sdk_semantics':'passed'},artifact_name=stem)
    except SdkFailure as exc:
        result['blocker']=dict(code=exc.code,message=str(exc))
        if exc.report is not None:result['sdk_diagnostics']=exc.report
        if getattr(exc,'encrypted_log',None)is not None:result['encrypted_failure_log']=exc.encrypted_log
    except BuildFailure as exc:result['blocker']=dict(code=exc.code,message=str(exc))
    except (ArtifactError,OSError,ValueError,RuntimeError,probe.ProbeError):result['blocker']=dict(code='sdk_producer_failed',message='Native SDK producer failed during '+result['phase'])
    (output/('bloom-build-'+target+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    return 0 if result['status']=='passed'else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner',choices=probe.TARGETS,required=True);parser.add_argument('--revision',required=True)
    parser.add_argument('--version',required=True);parser.add_argument('--sdk-file',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    return build(parser.parse_args())


if __name__=='__main__':raise SystemExit(main())
