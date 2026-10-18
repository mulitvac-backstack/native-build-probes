#!/usr/bin/env python3
"""Trusted native Headspace release lane; private SDK stays in ephemeral runner.

No private source/log uploads. Package outputs use a strict format/hash allowlist.
Gitea publication is a separate owner-operated step; no credentials here.
"""
import argparse
import base64
import hashlib
import gzip
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
import tarfile
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import probe
from headspace_source_build import BuildFailure, SOURCE_URL, FORMATS, fetch_source, run, validate_revision

MAX_ARCHIVE = 512 * 1024
MAX_EXTRACTED = 128 * 1024 * 1024
ALLOWED_ENV = {'BLOOM_LIB_DIR', 'BLOOM_STATIC', 'BLOOM_STATIC_LIBS', 'BLOOM_EXTRA_LIB_DIRS'}


def sdk_count(value):
    if not isinstance(value, str) or re.fullmatch(r'(?:[1-9]|1[0-9]|2[0-4])', value) is None:
        raise BuildFailure('sdk_configuration', 'SDK chunk count must be 1..24')
    return int(value)


def append_sdk(path, index, chunk, count):
    """One secret at a time avoids Windows' aggregate environment-size limit."""
    if not 1 <= index <= 24:
        raise BuildFailure('sdk_configuration', 'SDK chunk index out of range')
    if index > count:
        if chunk:
            raise BuildFailure('sdk_configuration', 'Unexpected SDK chunk beyond declared count')
        return
    if not chunk or len(chunk) > 12288 or re.fullmatch(r'[A-Za-z0-9+/=]+', chunk) is None:
        raise BuildFailure('sdk_configuration', 'Missing or invalid SDK chunk')
    path.parent.mkdir(parents=True, exist_ok=True)
    if index == 1:
        # Owned fixed RUNNER_TEMP file, no host location or arbitrary config.
        path.write_text('', encoding='ascii'); path.chmod(0o600)
    if not path.is_file() or path.is_symlink():
        raise BuildFailure('sdk_configuration', 'SDK assembly file unavailable')
    with path.open('a', encoding='ascii') as handle:
        handle.write(chunk)
    if path.stat().st_size > MAX_ARCHIVE * 2:
        raise BuildFailure('sdk_configuration', 'SDK encoded archive exceeds limit')


def extract_sdk(encoded, expected_sha, destination):
    if re.fullmatch(r'[0-9a-f]{64}', expected_sha or '') is None:
        raise BuildFailure('sdk_configuration', 'SDK SHA256 must be 64 lowercase hex characters')
    if encoded.is_symlink() or encoded.stat().st_size > MAX_ARCHIVE * 2:
        raise BuildFailure('sdk_archive_invalid', 'Encoded SDK input exceeds bounds')
    try:
        payload = base64.b64decode(encoded.read_bytes(), validate=True)
    except ValueError as exc:
        raise BuildFailure('sdk_archive_invalid', 'SDK Base64 validation failed') from exc
    if len(payload) > MAX_ARCHIVE or hashlib.sha256(payload).hexdigest() != expected_sha:
        raise BuildFailure('sdk_archive_invalid', 'SDK archive checksum or size mismatch')
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or any(destination.iterdir()):
        raise BuildFailure('sdk_archive_invalid', 'SDK destination must be empty')
    with tempfile.TemporaryFile() as archive_file:
        try:
            # Bound decompression before tar/PAX metadata parsing, not merely
            # each declared member after the archive parser has read it.
            import io
            with gzip.GzipFile(fileobj=io.BytesIO(payload)) as compressed:
                expanded=0
                while True:
                    block=compressed.read(1024*1024)
                    if not block:break
                    expanded+=len(block)
                    if expanded>MAX_EXTRACTED+8*1024*1024:
                        raise BuildFailure('sdk_archive_invalid','SDK tar stream exceeds decompression limit')
                    archive_file.write(block)
            archive_file.seek(0)
            with tarfile.open(fileobj=archive_file, mode='r:') as archive:
                members = archive.getmembers(); seen=set(); total=0
                if len(members)>10000:
                    raise BuildFailure('sdk_archive_invalid','SDK file count exceeds limit')
                for member in members:
                    name = member.name
                    path = PurePosixPath(name)
                    if (not (name.startswith('bloomdb/') or (name=='bloomdb' and member.isdir())) or name.startswith('/') or '\\' in name
                        or ':' in name or any(p in ('..','.') for p in path.parts)
                        or not (member.isfile() or member.isdir()) or name in seen):
                        raise BuildFailure('sdk_archive_invalid','SDK archive has unsafe or duplicate entry')
                    seen.add(name); total+=member.size
                    if total>MAX_EXTRACTED or member.size>32*1024*1024:
                        raise BuildFailure('sdk_archive_invalid','SDK extracted size exceeds limit')
                for member in members:
                    path = destination.joinpath(*PurePosixPath(member.name).parts)
                    if member.isdir():
                        path.mkdir(parents=True,exist_ok=True)
                    else:
                        path.parent.mkdir(parents=True,exist_ok=True)
                        stream=archive.extractfile(member)
                        with path.open('xb') as handle:shutil.copyfileobj(stream,handle)
                        path.chmod(0o600)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise BuildFailure('sdk_archive_invalid','SDK archive extraction failed') from exc
    return destination/'bloomdb'


def pinned_sdk_sha(source, configured):
    path=source/'docs/release/bloom-sdk-input.json'
    if path.is_symlink() or not path.is_file() or path.stat().st_size>65536:
        raise BuildFailure('sdk_pin_missing','Source revision must include bounded pinned SDK input manifest')
    document=json.loads(path.read_text())
    expected=document.get('archive_sha256')
    if not isinstance(expected,str)or re.fullmatch('[0-9a-f]{64}',expected)is None:
        raise BuildFailure('sdk_pin_invalid','Source SDK digest must be 64 lowercase hexadecimal characters')
    if configured!=expected:
        raise BuildFailure('sdk_pin_mismatch','Encrypted SDK configuration does not match this source revision')
    return expected


def artifact_receipt(directory, target, revision):
    inventory=directory/('inventory-'+target+'.json')
    if inventory.is_symlink() or not inventory.is_file() or inventory.stat().st_size>65536:
        raise BuildFailure('artifact_inventory','Missing or oversized package inventory')
    doc=json.loads(inventory.read_text())
    if doc.get('target')!=target or doc.get('source_revision')!=revision:
        raise BuildFailure('artifact_inventory','Package source/target identity mismatch')
    expected=FORMATS[probe.TARGETS[next(k for k,v in probe.TARGETS.items() if v[2]==target)][0]]
    observed=set()
    files=doc.get('files',[])
    if not files or len(files)>12:
        raise BuildFailure('artifact_inventory','Invalid artifact count')
    for entry in files:
        name=entry.get('path','');fmt=entry.get('format')
        path=directory/name
        expected_stem='headspace-'+doc.get('version','')+'-'+target
        allowed_names={expected_stem+extension for extension in ['.deb','.rpm','.app.zip','.dmg','.pkg','.rb','.msi','.winget.zip']}
        if (name not in allowed_names or '/' in name or '\\' in name
            or fmt not in expected or not path.is_file() or path.is_symlink()
            or path.stat().st_size>1024*1024*1024):
            raise BuildFailure('artifact_inventory','Artifact does not match compiled-package allowlist')
        digest=hashlib.sha256()
        with path.open('rb')as handle:
            for block in iter(lambda:handle.read(1024*1024),b''):digest.update(block)
        if digest.hexdigest()!=entry.get('sha256'):
            raise BuildFailure('artifact_inventory','Artifact checksum mismatch')
        observed.add(fmt)
    if observed!=set(expected):
        raise BuildFailure('artifact_inventory','Required package formats missing')
    return doc


def product_cargo_command(rust, target, subcommand):
    command=rust[:-1]+['cargo',subcommand,'--locked','--target',target]
    if subcommand=='test':
        command+=['-p','headspace-core','-p','headspace-ai','-p','headspace-mcp','-p','headspace-gpui']
    elif subcommand=='build':
        command+=['--release','-p','headspace-gpui','-p','headspace-mcp']
    else:
        raise BuildFailure('cargo_contract','Unsupported product build operation')
    return command


def build(args):
    revision=validate_revision(args.revision)
    identity=probe.machine_identity()
    probe.validate_native(args.runner,identity['os'],identity['native_arch'],identity['process_arch'],identity['translated'])
    system,arch,target=probe.TARGETS[args.runner]
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    result=dict(source=SOURCE_URL,source_revision=revision,target=target,runner=args.runner,status='failed',phase='source_fetch',formats=dict.fromkeys(FORMATS[system],'not_run'))
    try:
        with tempfile.TemporaryDirectory(prefix='headspace-private-release-')as temporary:
            source=Path(temporary)/'source';fetch_source(source,revision)
            candidate=Path(temporary)/'packages';candidate.mkdir()
            result['phase']='sdk_extract'
            sdk_sha=pinned_sdk_sha(source,os.environ.get('BLOOM_SDK_SHA256',''))
            result['sdk_archive_sha256']=sdk_sha
            sdk=extract_sdk(args.sdk_file,sdk_sha,source/'.private')
            result['phase']='native_toolchain'
            rust,_=probe.rust_tool(args.runner,True)
            env=probe.windows_compiler_env(arch)if system=='Windows'else os.environ.copy()
            # No secret chunks are forwarded to compilers or package tools.
            for key in list(env):
                if key.startswith('BLOOM_SDK_'):env.pop(key)
            env.update(CARGO_TERM_COLOR='never',CARGO_INCREMENTAL='0')
            env['CARGO_TARGET_DIR']=str(Path(temporary)/'target')
            env_file=Path(temporary)/'sdk-env.json'
            result['phase']='sdk_build'
            run([sys.executable,str(source/'scripts/ci/build_bloom.py'),'--source',str(sdk),'--output',str(source/'.private/bloom-sdk'),'--env-json',str(env_file),'--target',target],'sdk_build',cwd=source,env=env,timeout=900)
            sdk_env=json.loads(env_file.read_text())
            if not isinstance(sdk_env,dict)or not sdk_env or set(sdk_env)-ALLOWED_ENV or any(not isinstance(v,str)for v in sdk_env.values()):
                raise BuildFailure('sdk_environment','SDK builder returned an unsupported environment contract')
            env.update(sdk_env)
            for phase,sub in [('cargo_test','test'),('cargo_build','build')]:
                result['phase']=phase
                command=product_cargo_command(rust,target,sub)
                run(command,phase,cwd=source,env=env,timeout=2400);result[phase]='passed'
            result['phase']='package'
            for fmt in FORMATS[system]:
                result['formats'][fmt]='running'
                run([sys.executable,str(source/'scripts/package.py'),'--target',target,'--format',fmt,'--output',str(candidate)],'package_'+fmt,cwd=source,env=env,timeout=600)
                result['formats'][fmt]='created_unsigned_not_runtime_qualified'
            result['phase']='artifact_audit';receipt=artifact_receipt(candidate,target,revision)
            result['artifact_count']=len(receipt['files'])
            verifier=source/'scripts/verify-release.py'
            if verifier.is_file():
                for entry in receipt['files']:
                    if entry['format']not in ('deb','rpm','dmg','pkg','msi'):continue
                    report=output/('verify-'+target+'-'+entry['format']+'.json')
                    base=[sys.executable,str(verifier),'--runner',args.runner,'--target',target,'--format',entry['format'],'--artifact',str(candidate/entry['path']),'--inventory',str(candidate/('inventory-'+target+'.json')),'--source-revision',revision]
                    run(base+['--report',str(report),'--mode','audit'],'verify_'+entry['format'],cwd=source,env=env,timeout=600)
                    install_report=output/('verify-install-'+target+'-'+entry['format']+'.json')
                    qualification=result.setdefault('native_qualification',{})
                    try:
                        run(base+['--report',str(install_report),'--mode','install'],'install_'+entry['format'],cwd=source,env=env,timeout=900)
                        qualification[entry['format']]='passed'
                    except BuildFailure as exc:
                        # Compiled unsigned development packages survive a real
                        # runtime/installer block; final release does not pass.
                        qualification[entry['format']]=dict(status='blocked_or_failed',code=exc.code,report=install_report.name)
                    for public_report in [report,install_report]:
                        if public_report.is_symlink() or (public_report.exists() and public_report.stat().st_size>65536):
                            public_report.unlink(missing_ok=True)
                            raise BuildFailure('verification_report','Native report exceeds public receipt bounds')
            else:
                result['native_qualification']=dict(status='blocked',reason='Source revision has no native verifier')
            # Only validated compiled artifacts cross into the upload directory.
            for entry in receipt['files']:
                shutil.copyfile(candidate/entry['path'],output/entry['path'])
            (output/('inventory-'+target+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
            result.update(status='passed',phase='completed')
    except BuildFailure as exc:
        result['blocker']=dict(code=exc.code,message=str(exc))
    except (OSError,ValueError,RuntimeError,probe.ProbeError):
        result['blocker']=dict(code='release_adapter_failed',message='Native release lane failed during '+result['phase'])
    report=output/('build-'+target+'.json');report.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
    summary=os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary,'a')as handle:handle.write('## Native package result\n\n```json\n'+json.dumps(result,indent=2)+'\n```\n')
    return 0 if result['status']=='passed'else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    append=sub.add_parser('append-sdk');append.add_argument('--index',type=int,required=True);append.add_argument('--file',type=Path,required=True)
    release=sub.add_parser('build');release.add_argument('--runner',choices=probe.TARGETS,required=True);release.add_argument('--revision',required=True);release.add_argument('--sdk-file',type=Path,required=True);release.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='append-sdk':append_sdk(args.file,args.index,os.environ.get('HEADSPACE_SDK_CHUNK',''),sdk_count(os.environ.get('BLOOM_SDK_CHUNKS')));return 0
        return build(args)
    except (BuildFailure,OSError)as exc:
        print(json.dumps(dict(status='failed',code=getattr(exc,'code','io_failure'),message=str(exc)[:500])));return 1


if __name__=='__main__':raise SystemExit(main())
