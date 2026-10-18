#!/usr/bin/env python3
"""Build one immutable public Headspace revision on a fixed native runner.

This adapter never substitutes compiler fixtures or successful skipped packages
for real product checks. Product-owned scripts/package.py receives --target and
one --format at a time. A zero exit records recipe completion only, not installer
runtime/signing qualification or published artifacts.
"""
import argparse
import json
import os
from pathlib import Path, PureWindowsPath
import re
import signal
import subprocess
import sys
import tempfile
import time
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import probe  # noqa: E402 -- share the already-qualified native identity checks

SOURCE_URL = "https://git.multivac.network/backstack.io/headspace.git"
FORMATS = {"Linux": ("deb", "rpm"), "Darwin": ("app", "dmg", "pkg", "homebrew"),
           "Windows": ("msi", "winget")}
MAX_FINDINGS = 20
MAX_LOG_BYTES = 16 * 1024 * 1024
RECIPE = "scripts/package.py"


class BuildFailure(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message[:500])


def validate_revision(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{40}", value) is None:
        raise BuildFailure("invalid_revision", "source_revision must be exactly 40 hexadecimal characters")
    return value.lower()


def contained(root, path):
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def dependency_tables(document, prefix=""):
    """Find Cargo dependency tables, including workspace and target overrides."""
    for name, value in document.items():
        if not isinstance(value, dict):
            continue
        key = prefix + name
        if name in ("dependencies", "dev-dependencies", "build-dependencies", "patch", "replace"):
            # patch has a registry layer; replace/dependencies have direct specs.
            if name == "patch":
                for registry, entries in value.items():
                    if isinstance(entries, dict):
                        yield key + "." + registry, entries
            else:
                yield key, value
        elif name != "metadata":
            yield from dependency_tables(value, key + ".")


def preflight(source):
    """Inspect manifests without ever following paths outside the public tree."""
    source = source.resolve()
    if not (source / "Cargo.toml").is_file():
        raise BuildFailure("missing_workspace", "Public source has no root Cargo.toml")
    findings = []
    count = 0
    manifests = 0

    def add(manifest, code, dependency, detail):
        nonlocal count
        count += 1
        if len(findings) < MAX_FINDINGS:
            findings.append({"manifest": manifest[:180], "code": code,
                             "dependency": dependency[:100], "detail": detail[:200]})

    # os.walk does not follow directory symlinks. A symlinked manifest itself is
    # checked before reading; hidden SDK/config manifests are still inspected.
    for directory, subdirs, files in os.walk(source, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if d not in (".git", "target", "node_modules"))
        if "Cargo.toml" not in files:
            continue
        manifests += 1
        if manifests > 1000:
            raise BuildFailure("manifest_budget", "More than 1000 Cargo manifests; preflight stopped")
        manifest = Path(directory) / "Cargo.toml"
        label = manifest.relative_to(source).as_posix()
        if not contained(source, manifest):
            add(label, "manifest_outside_source", "", "Symlinked manifest escapes source checkout")
            continue
        if manifest.stat().st_size > 1024 * 1024:
            add(label, "manifest_budget", "", "Manifest exceeds 1 MiB inspection limit")
            continue
        try:
            document = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            add(label, "invalid_manifest", "", "Cargo manifest could not be parsed")
            continue
        for table, entries in dependency_tables(document):
            for name, spec in entries.items():
                if not isinstance(spec, dict) or "path" not in spec:
                    continue
                value = spec["path"]
                dependency = table + "." + name
                if not isinstance(value, str) or not value:
                    add(label, "invalid_dependency_path", dependency, "Path must be a nonempty string")
                elif Path(value).is_absolute() or PureWindowsPath(value).drive or value.startswith("\\"):
                    add(label, "absolute_dependency_path", dependency, "Cargo path dependency must be relative to public source")
                else:
                    # Reject Windows separators on Unix too: portability must not
                    # depend on the runner interpreting a different path grammar.
                    target = manifest.parent / value.replace("\\", "/")
                    if not contained(source, target):
                        add(label, "dependency_outside_source", dependency, "Cargo dependency escapes public source checkout")
                    elif not target.is_dir() or not (target / "Cargo.toml").is_file():
                        add(label, "missing_path_dependency", dependency, "Cargo dependency is absent from public source checkout")
                    elif not contained(source, target / "Cargo.toml"):
                        add(label, "dependency_outside_source", dependency, "Cargo dependency manifest escapes public source checkout")
    return {"manifests_checked": manifests, "finding_count": count, "findings": findings,
            "omitted_findings": count - len(findings)}


def stop_child(child):
    if child.poll() is not None:
        return
    if os.name == "posix":
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    else:
        # Only our still-running subprocess tree, never an arbitrary command/PID.
        subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False)
        if child.poll() is None:
            child.kill()
    child.wait(timeout=15)


def run(command, phase, cwd=None, env=None, timeout=600):
    """Bounded subprocess logs; no raw commands, environment or credential dumps."""
    with tempfile.TemporaryFile() as output:
        try:
            child = subprocess.Popen(command, cwd=cwd, env=env, stdout=output, stderr=output,
                                     shell=False, start_new_session=os.name == "posix")
        except OSError as exc:
            raise BuildFailure(phase + "_unavailable", "Required executable unavailable during " + phase) from exc
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if time.monotonic() >= deadline:
                stop_child(child)
                raise BuildFailure(phase + "_timeout", "Time limit exceeded during " + phase)
            if os.fstat(output.fileno()).st_size > MAX_LOG_BYTES:
                stop_child(child)
                raise BuildFailure(phase + "_output_limit", "Log size limit exceeded during " + phase)
            time.sleep(0.1)
        size = os.fstat(output.fileno()).st_size
        if size > MAX_LOG_BYTES:
            raise BuildFailure(phase + "_output_limit", "Log size limit exceeded during " + phase)
        if child.returncode:
            # Public fixed-revision build failures are classified without printing
            # potentially arbitrary build-script output into the report.
            raise BuildFailure(phase + "_failed", "Command exited " + str(child.returncode) + " during " + phase)
        if size > 4096:
            return ""  # Only tiny identity/commit commands consume returned output.
        output.seek(0)
        return output.read().decode("utf-8", errors="replace").strip()


def fetch_source(source, revision, execute=run):
    env = os.environ.copy()
    env.update(GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="Never")
    git = ["git", "-c", "credential.helper=", "-c", "core.askPass=", "-c", "credential.interactive=false"]
    execute(git + ["init", str(source)], "source_fetch", env=env, timeout=60)
    execute(git + ["remote", "add", "origin", SOURCE_URL], "source_fetch", cwd=source, env=env, timeout=30)
    execute(git + ["fetch", "--depth=1", "origin", revision], "source_fetch", cwd=source, env=env, timeout=120)
    execute(git + ["checkout", "--detach", "FETCH_HEAD"], "source_fetch", cwd=source, env=env, timeout=60)
    actual = execute(git + ["rev-parse", "HEAD"], "source_fetch", cwd=source, env=env, timeout=30)
    if actual != revision:
        raise BuildFailure("source_revision_mismatch", "Fetched HEAD does not match requested immutable revision")


def package(source, target, formats, execute=run, env=None):
    recipe = source / RECIPE
    if not recipe.is_file() or not contained(source, recipe):
        raise BuildFailure("package_recipe_missing", "Public source must provide contained " + RECIPE)
    for format_name in formats:
        formats[format_name] = "running"
        try:
            execute([sys.executable, str(recipe), "--target", target, "--format", format_name],
                    "package_" + format_name, cwd=source, env=env, timeout=300)
        except BuildFailure:
            formats[format_name] = "failed"
            raise
        formats[format_name] = "recipe_completed_artifacts_not_qualified"


def emit(result, summary=None):
    encoded = json.dumps(result, sort_keys=True, indent=2)
    # All report fields are bounded above; enforce a final machine-readable cap.
    if len(encoded.encode("utf-8")) > 16384:
        result["preflight"].pop("findings", None)
        result["preflight"]["details_omitted"] = True
        encoded = json.dumps(result, sort_keys=True, indent=2)
    print(encoded)
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("## Headspace real source build\n\n```json\n" + encoded.replace("```", "\\u0060\\u0060\\u0060") + "\n```\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, choices=probe.TARGETS)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--install-rust", action="store_true")
    args = parser.parse_args(argv)
    system, arch, target = probe.TARGETS[args.runner]
    result = {"schema_version": 1, "source": SOURCE_URL, "source_revision": None,
              "runner": args.runner, "expected_os": system, "expected_arch": arch,
              "target": target, "phase": "input", "status": "failed",
              "formats": {name: "not_run" for name in FORMATS[system]},
              "runtime_install_signing_publication": "not_tested"}
    try:
        revision = validate_revision(args.revision)
        result["source_revision"] = revision
        result["phase"] = "native_identity"
        identity = probe.machine_identity()
        result["machine"] = identity
        probe.validate_native(args.runner, identity["os"], identity["native_arch"],
                              identity["process_arch"], identity["translated"])
        with tempfile.TemporaryDirectory(prefix="headspace-source-build-") as directory:
            source = Path(directory) / "source"
            result["phase"] = "source_fetch"
            fetch_source(source, revision)
            result["verified_source_revision"] = revision
            result["phase"] = "preflight"
            result["preflight"] = preflight(source)
            if result["preflight"]["finding_count"]:
                raise BuildFailure("nonportable_source_dependencies", "Public source Cargo path dependency preflight failed")
            result["phase"] = "toolchain"
            rust_command, verbose = probe.rust_tool(args.runner, args.install_rust)
            result["rust_host"] = probe.rust_host(verbose)
            result["rust_version"] = probe.RUST_VERSION
            env = probe.windows_compiler_env(arch) if system == "Windows" else os.environ.copy()
            env.update(CARGO_TERM_COLOR="never", CARGO_INCREMENTAL="0")
            cargo = rust_command[:-1] + ["cargo"]
            for phase, subcommand in (("cargo_test", "test"), ("cargo_build", "build")):
                result["phase"] = phase
                command = cargo + [subcommand, "--workspace", "--locked", "--target", target]
                if subcommand == "build":
                    command.append("--release")
                run(command, phase, cwd=source, env=env, timeout=900)
                result[phase] = "passed"
            result["phase"] = "package"
            package(source, target, result["formats"], env=env)
            result.update(status="passed", phase="completed")
    except BuildFailure as exc:
        result["blocker"] = {"code": exc.code, "message": str(exc)}
    except probe.ProbeError:
        result["blocker"] = {"code": result["phase"] + "_failed",
                             "message": "Native identity or fixed toolchain preparation failed"}
    except (OSError, ValueError, RuntimeError):
        result["blocker"] = {"code": "adapter_error", "message": "Source/build adapter failed during " + result["phase"]}
    emit(result, os.environ.get("GITHUB_STEP_SUMMARY"))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
