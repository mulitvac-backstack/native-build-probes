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
import subprocess
import time
import sys
import tarfile
import tempfile
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import probe
from headspace_source_build import BuildFailure, SOURCE_URL, FORMATS, fetch_source, run, validate_revision, stop_child, MAX_LOG_BYTES

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


class SdkFailure(BuildFailure):
    def __init__(self,code,message,report=None):
        self.report=report
        super().__init__(code,message)


def safe_sdk_report(output, allowed_files):
    """Forward only verified relative source coordinates/compiler codes."""
    for line in output.splitlines():
        if len(line)>8192:continue
        try:document=json.loads(line)
        except ValueError:continue
        if not isinstance(document,dict)or document.get('phase')not in ('configure','compile','test','install'):continue
        exit_code=document.get('exit_code')
        if type(exit_code)is not int or not -255<=exit_code<=4294967295:continue
        diagnostics=[]
        candidates=document.get('diagnostics',[])
        if not isinstance(candidates,list):continue
        for entry in candidates[:20]:
            if not isinstance(entry,dict):continue
            item={}
            file=entry.get('file');location=entry.get('line');code=entry.get('code')
            if isinstance(file,str)and file in allowed_files and len(file)<=200 and type(location)is int and 1<=location<=10000000:
                item.update(file=file,line=location)
            if isinstance(code,str)and re.fullmatch(r'(?:C[0-9]{4}|LNK[0-9]{4}|E[0-9]{4})',code):item['code']=code
            if item:diagnostics.append(item)
        return dict(phase=document['phase'],exit_code=exit_code,diagnostics=diagnostics)
    return None


def run_sdk(command,source,env,timeout=900):
    allowed={'adapter/platform.c','adapter/platform.h','adapter/sdk_smoke.c'}
    manifest=json.loads((source/'docs/release/bloom-sdk-input.json').read_text())
    diagnostic_files=manifest.get('diagnostic_files',[])
    if not isinstance(diagnostic_files,list)or len(diagnostic_files)>100:
        raise SdkFailure('sdk_diagnostic_contract','Source diagnostic allowlist exceeds bounds')
    for name in diagnostic_files:
        if not isinstance(name,str)or len(name)>200 or PurePosixPath(name).is_absolute()or '\\'in name or ':'in name or any(part in ('.','..')for part in name.split('/')):
            raise SdkFailure('sdk_diagnostic_contract','Source diagnostic allowlist contains invalid relative path')
        allowed.add(name)
    with tempfile.TemporaryFile()as output:
        try:child=subprocess.Popen(command,cwd=source,env=env,stdout=output,stderr=output,shell=False,start_new_session=os.name=='posix')
        except OSError as exc:raise SdkFailure('sdk_build_unavailable','Native SDK driver unavailable')from exc
        deadline=time.monotonic()+timeout
        while child.poll()is None:
            if time.monotonic()>=deadline:
                stop_child(child);raise SdkFailure('sdk_build_timeout','Native SDK driver exceeded time limit')
            if os.fstat(output.fileno()).st_size>MAX_LOG_BYTES:
                stop_child(child);raise SdkFailure('sdk_build_output_limit','Native SDK driver exceeded private log bound')
            time.sleep(0.1)
        if child.returncode:
            size=os.fstat(output.fileno()).st_size
            output.seek(max(0,size-65536))
            report=safe_sdk_report(output.read(65536).decode('utf-8',errors='replace'),allowed)
            raise SdkFailure('sdk_build_failed','Native SDK driver failed; raw compiler output remains private',report)


class CargoFailure(SdkFailure):
    pass


def safe_cargo_report(output, allowed_public, allowed_sdk):
    diagnostics=[]
    for line in output.splitlines():
        if len(line)>65536:continue
        try:document=json.loads(line)
        except ValueError:continue
        if not isinstance(document,dict)or document.get('reason')!='compiler-message':continue
        message=document.get('message',{})
        if not isinstance(message,dict)or message.get('level')not in ('error','failure-note'):continue
        code=message.get('code');code=code.get('code')if isinstance(code,dict)else None
        for span in message.get('spans',[])[:8]:
            if not isinstance(span,dict)or not span.get('is_primary'):continue
            filename=span.get('file_name');location=span.get('line_start');item={}
            if isinstance(filename,str):
                name=filename.replace('\\','/')
                if name in allowed_public and len(name)<=200:item['file']=name
                elif name.startswith('.private/bloomdb/')and name[len('.private/bloomdb/'):]in allowed_sdk:item['file']='sdk/'+name[len('.private/bloomdb/'):]
            if item and type(location)is int and 1<=location<=10000000:item['line']=location
            if isinstance(code,str)and re.fullmatch('E[0-9]{4}',code):item['code']=code
            if item and item not in diagnostics:diagnostics.append(item)
            if len(diagnostics)>=20:break
        if len(diagnostics)>=20:break
    patterns={'locked_dependency_update_required':['lock file','--locked'],
              'dependency_fetch_failed':['failed to get'],
              'dependency_fetch_or_revision_failed':['failed to fetch'],
              'dependency_resolution_failed':['failed to select a version'],
              'native_dependency_build_failed':['failed to run custom build command'],
              'rust_toolchain_incompatible':['requires rustc']}
    classifications=[name for name,words in patterns.items()if all(word in output for word in words)]
    return dict(diagnostics=diagnostics,classifications=classifications)


def run_cargo(command,phase,source,env,timeout=2400):
    allowed_public=set()
    for path in source.rglob('*.rs'):
        relative=path.relative_to(source)
        if relative.parts[0]not in ('.private','target','.git')and not path.is_symlink():allowed_public.add(relative.as_posix())
    manifest=json.loads((source/'docs/release/bloom-sdk-input.json').read_text())
    allowed_sdk=set(manifest.get('diagnostic_files',[]))
    with tempfile.TemporaryFile()as output:
        try:child=subprocess.Popen(command,cwd=source,env=env,stdout=output,stderr=output,shell=False,start_new_session=os.name=='posix')
        except OSError as exc:raise CargoFailure(phase+'_unavailable','Native Cargo executable unavailable')from exc
        deadline=time.monotonic()+timeout
        while child.poll()is None:
            if time.monotonic()>=deadline:
                stop_child(child);raise CargoFailure(phase+'_timeout','Native Cargo exceeded time limit')
            if os.fstat(output.fileno()).st_size>MAX_LOG_BYTES:
                stop_child(child);raise CargoFailure(phase+'_output_limit','Native Cargo exceeded private log bound')
            time.sleep(0.1)
        size=os.fstat(output.fileno()).st_size
        if size>MAX_LOG_BYTES:raise CargoFailure(phase+'_output_limit','Native Cargo exceeded private log bound')
        if child.returncode:
            output.seek(max(0,size-1024*1024))
            report=safe_cargo_report(output.read(1024*1024).decode('utf-8',errors='replace'),allowed_public,allowed_sdk)
            raise CargoFailure(phase+'_failed','Native Cargo failed; raw output remains private',report)


def validate_version(value):
    pattern=r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
    match=re.fullmatch(pattern,value)if isinstance(value,str)and len(value)<=128 else None
    if not match or (match[4]and any(p.isdigit()and len(p)>1 and p.startswith('0')for p in match[4].split('.'))):
        raise BuildFailure('version_invalid','Version must be exact SemVer without a v prefix')
    return value


def source_version(source, requested):
    value=tomllib.loads((source/'Cargo.toml').read_text())['workspace']['package']['version']
    validate_version(value)
    if requested!=value:
        raise BuildFailure('version_source_mismatch','Requested version differs from immutable Cargo workspace version')
    return value


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


def artifact_receipt(directory, target, revision, version=None):
    inventory=directory/('inventory-'+target+'.json')
    if inventory.is_symlink() or not inventory.is_file() or inventory.stat().st_size>65536:
        raise BuildFailure('artifact_inventory','Missing or oversized package inventory')
    doc=json.loads(inventory.read_text())
    if doc.get('target')!=target or doc.get('source_revision')!=revision or (version is not None and doc.get('version')!=version):
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
    command=rust[:-1]+['cargo',subcommand,'--locked','--target',target,'--message-format=json']
    if subcommand=='test':
        command+=['-p','headspace-core','-p','headspace-ai','-p','headspace-mcp','-p','headspace-gpui']
    elif subcommand=='build':
        command+=['--release','-p','headspace-gpui','-p','headspace-mcp','--features','headspace-gpui/native-profiler']
    else:
        raise BuildFailure('cargo_contract','Unsupported product build operation')
    return command


def build(args):
    revision=validate_revision(args.revision)
    version=validate_version(args.version)
    identity=probe.machine_identity()
    probe.validate_native(args.runner,identity['os'],identity['native_arch'],identity['process_arch'],identity['translated'])
    system,arch,target=probe.TARGETS[args.runner]
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    result=dict(source=SOURCE_URL,source_revision=revision,version=version,target=target,runner=args.runner,status='failed',phase='source_fetch',formats=dict.fromkeys(FORMATS[system],'not_run'))
    try:
        with tempfile.TemporaryDirectory(prefix='headspace-private-release-')as temporary:
            source=Path(temporary)/'source';fetch_source(source,revision)
            source_version(source,version)
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
            env.update(CARGO_TERM_COLOR='never',CARGO_INCREMENTAL='0',HEADSPACE_PACKAGE_VERSION=version,HEADSPACE_RELEASE_TAG='v'+version)
            env['CARGO_TARGET_DIR']=str(Path(temporary)/'target')
            env_file=Path(temporary)/'sdk-env.json'
            result['phase']='sdk_build'
            run_sdk([sys.executable,str(source/'scripts/ci/build_bloom.py'),'--source',str(sdk),'--output',str(source/'.private/bloom-sdk'),'--env-json',str(env_file),'--target',target],source,env,timeout=900)
            sdk_env=json.loads(env_file.read_text())
            if not isinstance(sdk_env,dict)or not sdk_env or set(sdk_env)-ALLOWED_ENV or any(not isinstance(v,str)for v in sdk_env.values()):
                raise BuildFailure('sdk_environment','SDK builder returned an unsupported environment contract')
            env.update(sdk_env)
            for phase,sub in [('cargo_test','test'),('cargo_build','build')]:
                result['phase']=phase
                command=product_cargo_command(rust,target,sub)
                run_cargo(command,phase,source,env,timeout=2400);result[phase]='passed'
            result['phase']='package'
            for fmt in FORMATS[system]:
                result['formats'][fmt]='running'
                run([sys.executable,str(source/'scripts/package.py'),'--target',target,'--format',fmt,'--output',str(candidate)],'package_'+fmt,cwd=source,env=env,timeout=600)
                result['formats'][fmt]='created_unsigned_not_runtime_qualified'
            result['phase']='artifact_audit';receipt=artifact_receipt(candidate,target,revision,version)
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
        if isinstance(exc,SdkFailure)and exc.report is not None:result['cargo_diagnostics'if isinstance(exc,CargoFailure)else'sdk_diagnostics']=exc.report
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
    release=sub.add_parser('build');release.add_argument('--runner',choices=probe.TARGETS,required=True);release.add_argument('--revision',required=True);release.add_argument('--version',required=True);release.add_argument('--sdk-file',type=Path,required=True);release.add_argument('--output',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='append-sdk':append_sdk(args.file,args.index,os.environ.get('HEADSPACE_SDK_CHUNK',''),sdk_count(os.environ.get('BLOOM_SDK_CHUNKS')));return 0
        return build(args)
    except (BuildFailure,OSError)as exc:
        print(json.dumps(dict(status='failed',code=getattr(exc,'code','io_failure'),message=str(exc)[:500])));return 1


if __name__=='__main__':raise SystemExit(main())
