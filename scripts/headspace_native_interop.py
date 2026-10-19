#!/usr/bin/env python3
"""Run fixed public-source native API fixtures; never build GPUI or Bloom."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import probe
from headspace_source_build import BuildFailure, fetch_source, stop_child

SOURCE_URL = "https://git.multivac.network/backstack.io/headspace.git"
MAX_LOG = 8 * 1024 * 1024
MAX_RECEIPT = 64 * 1024
HARNESSES = {
    "endpoint": ("native-live-endpoint", "passed_native_security_fixture"),
    "appkit": ("native-macos-interop", "passed_native_appkit_protocol_fixture"),
    "ole": ("native-windows-interop", "passed_native_ole_protocol_fixture"),
}


def revision(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise BuildFailure("invalid_revision", "Expected exact lowercase source SHA40")
    return value


def harnesses(label):
    system = probe.TARGETS[label][0]
    return ["endpoint"] + (["appkit"] if system == "Darwin" else ["ole"] if system == "Windows" else [])


def child_environment(environment):
    return {name: value for name, value in environment.items()
            if not name.startswith(("BLOOM_", "OPENAI_", "AWS_", "AZURE_", "CODEX_", "GH_", "GITHUB_", "ACTIONS_", "GITEA_"))
            and name not in ("NPM_TOKEN", "NODE_AUTH_TOKEN", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "CARGO_BUILD_TARGET")}


def run(command, phase, cwd=None, env=None, timeout=600):
    """Bound process/time/output; retain a bounded public-source diagnostic on failure."""
    with tempfile.TemporaryFile() as output:
        try:
            child = subprocess.Popen(command, cwd=cwd, env=env, stdout=output, stderr=output,
                                     shell=False, start_new_session=os.name == "posix")
        except OSError as error:
            raise BuildFailure(phase + "_unavailable", "Required native tool unavailable") from error
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if time.monotonic() >= deadline or os.fstat(output.fileno()).st_size > MAX_LOG:
                stop_child(child)
                raise BuildFailure(phase + "_bound", "Native fixture exceeded time/output bound")
            time.sleep(0.1)
        size = os.fstat(output.fileno()).st_size
        if size > MAX_LOG:
            raise BuildFailure(phase + "_bound", "Native fixture exceeded output bound")
        if child.returncode:
            output.seek(max(0, size - 12000))
            diagnostic = output.read(12000).decode(errors="replace")
            diagnostic = diagnostic.replace(str(Path.home()), "<home>")
            if cwd:
                diagnostic = diagnostic.replace(str(cwd), "<source>")
            failure = BuildFailure(phase + "_failed", "Public native fixture exited " + str(child.returncode))
            failure.diagnostic = diagnostic
            failure.exit_code = child.returncode
            raise failure
        output.seek(0)
        return output.read().decode(errors="replace").strip() if size <= 4096 else ""


def manifest(source, name):
    path = source / "experiments" / HARNESSES[name][0] / "Cargo.toml"
    for file in (path, path.with_name("Cargo.lock")):
        if file.is_symlink() or not file.is_file() or not file.resolve().is_relative_to(source.resolve()):
            raise BuildFailure("isolated_manifest_missing", "Expected contained manifest and lockfile")
    document = tomllib.loads(path.read_text())
    if "workspace" not in document:
        raise BuildFailure("nonisolated_workspace", "Native fixtures require their own Cargo workspace")
    def inspect(table):
        for key, value in table.items():
            if key.endswith("dependencies") and isinstance(value, dict):
                for package, spec in value.items():
                    if package in ("gpui", "gpui_platform", "bloomdb") or package.startswith("headspace-") or (isinstance(spec, dict) and ("path" in spec or "git" in spec)):
                        raise BuildFailure("nonisolated_dependency", "Native fixtures must use registry dependencies without GPUI/Bloom")
            elif isinstance(value, dict):
                inspect(value)
    inspect(document)
    return path


def receipt(path, name, label):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECEIPT:
        raise BuildFailure("invalid_native_receipt", "Expected bounded native JSON receipt")
    value = json.loads(path.read_text())
    expected = HARNESSES[name][1]
    if not isinstance(value, dict) or value.get("status") != expected or value.get("native_arch") != probe.TARGETS[label][1]:
        raise BuildFailure("native_receipt_identity", "Native fixture status/architecture differs")
    if name == "endpoint":
        expected_os = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}[probe.TARGETS[label][0]]
        if value.get("native_os") != expected_os or not re.fullmatch(r"[0-9a-f]{64}", value.get("production_module_sha256", "")):
            raise BuildFailure("native_receipt_identity", "Native endpoint source/OS differs")
    elif value.get("host_clipboard_read") is not False or value.get("host_clipboard_written") is not False or value.get("os_input_injected") is not False or value.get("gpui_or_bloom_compiled") is not False:
        raise BuildFailure("unsafe_native_fixture", "Native transfer receipt exceeds isolated fixture scope")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", choices=probe.TARGETS, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    result = dict(schema_version=1, status="failed", runner=args.runner, phase="identity", source_repository=SOURCE_URL,
                  source_revision=args.revision, rust_version=probe.RUST_VERSION, fixtures={},
                  scope="native endpoint security and OS transfer protocol fixtures, not physical browser gestures or full product qualification")
    try:
        source_revision = revision(args.revision)
        identity = probe.machine_identity()
        probe.validate_native(args.runner, identity["os"], identity["native_arch"], identity["process_arch"], identity["translated"])
        result["native_identity"] = identity
        result["phase"] = "rust_toolchain"
        rust_command, verbose = probe.rust_tool(args.runner, True)
        result["rust_host"] = probe.validate_rust(args.runner, verbose)
        env = child_environment(os.environ)
        if identity["os"] == "Windows":
            env = child_environment(probe.windows_compiler_env(identity["native_arch"]))
        env["CARGO_BUILD_JOBS"] = "4"
        with tempfile.TemporaryDirectory(prefix="headspace-native-interop-") as temporary:
            source = Path(temporary) / "source"
            result["phase"] = "source_fetch"
            fetch_source(source, source_revision, execute=run)
            env["CARGO_TARGET_DIR"] = str(Path(temporary) / "target")
            for name in harnesses(args.runner):
                result["phase"] = "native_" + name
                path = manifest(source, name)
                report = args.output / ("native-" + name + ".json")
                cargo = rust_command[:-1] + ["cargo", "run", "--locked", "--manifest-path", str(path), "--target", probe.TARGETS[args.runner][2], "--", str(report.resolve())]
                run(cargo, result["phase"], cwd=Path(temporary), env=env, timeout=600)
                result["fixtures"][name] = receipt(report, name, args.runner)
        result.update(status="passed_native_api_fixtures", phase="complete")
    except Exception as error:
        result["error_code"] = error.code if isinstance(error, BuildFailure) else "native_interop_failed"
        if isinstance(error, BuildFailure) and hasattr(error, "diagnostic"):
            result["diagnostic"] = error.diagnostic
            result["exit_code"] = error.exit_code
        else:
            result["diagnostic"] = str(error)[:1800]
    encoded = json.dumps(result, indent=2, sort_keys=True).encode()
    if len(encoded) > MAX_RECEIPT:
        result.pop("fixtures", None)
        result.update(status="failed", error_code="aggregate_receipt_bound")
        encoded = json.dumps(result, indent=2, sort_keys=True).encode()
    (args.output / "native-interop.json").write_bytes(encoded)
    print(encoded.decode())
    return 0 if result["status"] == "passed_native_api_fixtures" else 1


if __name__ == "__main__":
    raise SystemExit(main())
