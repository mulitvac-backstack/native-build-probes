"""Bounded native Bloom driver execution; raw compiler output stays private."""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

from bloom_profile import private_env
from sdk_artifacts import ArtifactError, MAX_FAILURE_LOG, encrypt_failure_log


class NativeFailure(ArtifactError):
    def __init__(self, code, report=None, encrypted_log=None):
        self.code, self.report, self.encrypted_log = code, report, encrypted_log
        super().__init__('Native Bloom SDK operation failed; raw output remains private')


def stop_child(child):
    if child.poll() is not None:
        return
    if os.name == 'posix':
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    else:
        subprocess.run(['taskkill', '/PID', str(child.pid), '/T', '/F'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        if os.name == 'posix':
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            child.kill()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            raise NativeFailure('sdk_stop_failed') from None


def safe_report(raw, allowed):
    for line in reversed(raw.splitlines()):
        if len(line) > 8192:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if (not isinstance(doc, dict) or doc.get('phase') not in ('configure', 'compile', 'test', 'install')
                or type(doc.get('exit_code')) is not int or not -255 <= doc['exit_code'] <= 4294967295
                or not isinstance(doc.get('diagnostics', []), list)):
            continue
        diagnostics = []
        for item in doc.get('diagnostics', [])[:20]:
            if not isinstance(item, dict):
                continue
            entry = {}
            if (isinstance(item.get('file'), str) and item['file'] in allowed and type(item.get('line')) is int
                    and 1 <= item['line'] <= 10_000_000):
                entry.update(file=item['file'], line=item['line'])
            if isinstance(item.get('code'), str) and re.fullmatch(r'(?:C[0-9]{4}|LNK[0-9]{4}|E[0-9]{4})', item['code']):
                entry['code'] = item['code']
            if entry:
                diagnostics.append(entry)
        return dict(phase=doc['phase'], exit_code=doc['exit_code'], diagnostics=diagnostics)
    return None


def run_driver(command, profile, sdk_output, env, failure_output, identity, timeout=900):
    profile, sdk_output = Path(profile), Path(sdk_output)
    inventory = json.loads((profile / 'source-inventory.json').read_text())
    allowed = {item['path'].removeprefix('input/bloomdb/') for item in inventory['files'] if item['path'].startswith('input/bloomdb/')}
    allowed |= {'adapter/platform.c', 'adapter/platform.h', 'adapter/sdk_smoke.c'}
    with tempfile.TemporaryFile() as output:
        try:
            child = subprocess.Popen(command, cwd=profile, env=private_env(env), stdout=output, stderr=output,
                                     shell=False, start_new_session=os.name == 'posix')
        except OSError:
            raise NativeFailure('sdk_build_unavailable') from None
        deadline = time.monotonic() + timeout
        failure = None
        while child.poll() is None:
            if time.monotonic() >= deadline:
                failure = 'sdk_build_timeout'
            elif os.fstat(output.fileno()).st_size > MAX_FAILURE_LOG:
                failure = 'sdk_build_output_limit'
            if failure:
                stop_child(child)
                break
            time.sleep(0.1)
        size = os.fstat(output.fileno()).st_size
        if size > MAX_FAILURE_LOG:
            failure = 'sdk_build_output_limit'
        if failure or child.returncode:
            output.seek(max(0, size - 65536))
            report = safe_report(output.read(65536).decode('utf-8', errors='replace'), allowed)
            log = sdk_output / 'private-build.log'
            if log.is_file() and not log.is_symlink() and log.resolve().is_relative_to(sdk_output.resolve()):
                total = log.stat().st_size
                with log.open('rb') as handle:
                    handle.seek(max(0, total - MAX_FAILURE_LOG))
                    raw = handle.read(MAX_FAILURE_LOG)
            else:
                total = size
                output.seek(max(0, total - MAX_FAILURE_LOG))
                raw = output.read(MAX_FAILURE_LOG)
            encrypted = dict(status='unavailable')
            try:
                ciphertext, metadata = encrypt_failure_log(raw, identity, total)
                destination = Path(failure_output)
                destination.mkdir(parents=True, exist_ok=True)
                stem = 'failure-' + identity['target'] + '-sdk_build'
                (destination / (stem + '.aesgcm')).write_bytes(ciphertext)
                (destination / (stem + '.manifest.json')).write_bytes(metadata)
                encrypted = dict(status='retained_encrypted', ciphertext=stem + '.aesgcm', manifest=stem + '.manifest.json')
            except (ArtifactError, OSError):
                pass
            raise NativeFailure(failure or 'sdk_build_failed', report, encrypted)
