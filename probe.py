#!/usr/bin/env python3
"""Bounded native compiler feasibility probe; no application or private inputs."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

RUST_VERSION = "1.98.1"
TARGETS = {
    "ubuntu-24.04": ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
    "ubuntu-24.04-arm": ("Linux", "aarch64", "aarch64-unknown-linux-gnu"),
    "windows-2025": ("Windows", "x86_64", "x86_64-pc-windows-msvc"),
    "windows-11-arm": ("Windows", "aarch64", "aarch64-pc-windows-msvc"),
    "macos-15-intel": ("Darwin", "x86_64", "x86_64-apple-darwin"),
    "macos-15": ("Darwin", "aarch64", "aarch64-apple-darwin"),
}


class ProbeError(Exception):
    pass


def normalize_arch(value):
    value = value.lower().strip()
    aliases = {"amd64": "x86_64", "x64": "x86_64", "x86_64": "x86_64",
               "arm64": "aarch64", "aarch64": "aarch64"}
    if value not in aliases:
        raise ProbeError("Unsupported architecture: " + value[:40])
    return aliases[value]


def rust_host(verbose):
    hosts = [line[6:].strip() for line in verbose.splitlines() if line.startswith("host: ")]
    if len(hosts) != 1:
        raise ProbeError("rustc did not report exactly one host target")
    return hosts[0]


def validate_native(label, system, native_arch, process_arch, translated=False):
    expected_os, expected_arch, _ = TARGETS[label]
    if system != expected_os:
        raise ProbeError("Operating system does not match runner label")
    if normalize_arch(native_arch) != expected_arch:
        raise ProbeError("Native machine architecture does not match runner label")
    if normalize_arch(process_arch) != expected_arch or translated:
        raise ProbeError("Emulated/translated probe process cannot qualify as native")


def validate_rust(label, verbose):
    host = rust_host(verbose)
    if host != TARGETS[label][2]:
        raise ProbeError("Rust host target does not match native runner target")
    release = [line[9:].strip() for line in verbose.splitlines() if line.startswith("release: ")]
    if release != [RUST_VERSION]:
        raise ProbeError("Rust release is not the fixed " + RUST_VERSION)
    return host


def run(command, cwd=None, timeout=90, env=None):
    try:
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                                text=True, errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError("Command unavailable or timed out: " + Path(command[0]).name) from exc
    if result.returncode:
        # Only fixed fixture/tool diagnostics; never print environment or whole commands.
        diagnostic = (result.stderr or result.stdout)[-1600:]
        diagnostic = diagnostic.replace(str(Path.home()), "<home>")
        if cwd:
            diagnostic = diagnostic.replace(str(cwd), "<fixture>")
        raise ProbeError(Path(command[0]).name + " failed: " + diagnostic.strip())
    return result.stdout.strip()


def machine_identity():
    system = platform.system()
    process = normalize_arch(platform.machine())
    translated = False
    if system == "Windows":
        # Unlike PROCESSOR_ARCHITECTURE, IsWow64Process2 reports native hardware.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        current = kernel.GetCurrentProcess
        current.restype = ctypes.c_void_p
        query = kernel.IsWow64Process2
        query.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort),
                          ctypes.POINTER(ctypes.c_ushort)]
        query.restype = ctypes.c_int
        process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
        if not query(current(), ctypes.byref(process_machine), ctypes.byref(native_machine)):
            raise ProbeError("Windows native architecture query failed")
        codes = {0x8664: "x86_64", 0xAA64: "aarch64"}
        if native_machine.value not in codes:
            raise ProbeError("Unsupported Windows native architecture")
        native = codes[native_machine.value]
        translated = process_machine.value != 0
    elif system == "Darwin":
        # hw.optional.arm64 identifies Apple Silicon even under Rosetta.
        arm = run(["sysctl", "-n", "hw.optional.arm64"])
        native = "aarch64" if arm == "1" else "x86_64"
        result = subprocess.run(["sysctl", "-n", "sysctl.proc_translated"],
                                capture_output=True, text=True, check=False)
        translated = result.returncode == 0 and result.stdout.strip() == "1"
    else:
        native = normalize_arch(os.uname().machine)
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ProbeError("Probe process must be 64-bit")
    return {"os": system, "native_arch": native, "process_arch": process,
            "translated": translated, "os_release": platform.release()[:120],
            "python_version": platform.python_version()}


def rust_tool(label, install):
    rustup = shutil.which("rustup")
    if not rustup:
        raise ProbeError("rustup missing; provision native Rust before running (no bootstrap download)")
    spec = RUST_VERSION + "-" + TARGETS[label][2]
    installed = run([rustup, "toolchain", "list"])
    if not any(line.split()[0] == spec for line in installed.splitlines() if line.split()):
        if not install:
            raise ProbeError("Fixed Rust toolchain missing; use --install-rust to install it")
        run([rustup, "toolchain", "install", spec, "--profile", "minimal", "--no-self-update"],
            timeout=420)
    command = [rustup, "run", spec, "rustc"]
    verbose = run(command + ["-vV"])
    validate_rust(label, verbose)
    return command, verbose


def windows_compiler_env(arch):
    # Use the installed VS tools, not a remote setup action or package installer.
    vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / \
        "Microsoft Visual Studio/Installer/vswhere.exe"
    if not vswhere.is_file():
        raise ProbeError("Visual Studio vswhere missing")
    installation = run([str(vswhere), "-latest", "-products", "*", "-property", "installationPath"])
    devcmd = Path(installation) / "Common7/Tools/VsDevCmd.bat"
    if not devcmd.is_file():
        raise ProbeError("Visual Studio developer shell missing")
    target = "arm64" if arch == "aarch64" else "x64"
    command = 'call "' + str(devcmd) + '" -no_logo -arch=' + target + \
              ' -host_arch=' + target + ' >nul && set'
    # Capture internally and retain only compiler configuration; never emit the dump.
    result = run(["cmd.exe", "/d", "/s", "/c", command])
    compiler_env = os.environ.copy()
    allow = {"path", "include", "lib", "libpath"}
    for line in result.splitlines():
        name, sep, value = line.partition("=")
        if sep and name.lower() in allow:
            compiler_env[name.upper()] = value
    return compiler_env


def fixture_sources(folder):
    (folder / "hello.rs").write_text('fn main() { println!("rust:{}", std::env::consts::ARCH); }\n')
    (folder / "hello.c").write_text('''#include <stdio.h>
#if defined(__aarch64__) || defined(_M_ARM64)
#define PROBE_ARCH "aarch64"
#elif defined(__x86_64__) || defined(_M_X64)
#define PROBE_ARCH "x86_64"
#else
#error unsupported native target
#endif
#define STR_INNER(x) #x
#define STR(x) STR_INNER(x)
#if defined(_MSC_FULL_VER)
#define COMPILER "MSVC " STR(_MSC_FULL_VER)
#elif defined(__clang__)
#define COMPILER "Clang " __clang_version__
#elif defined(__GNUC__)
#define COMPILER "GCC " __VERSION__
#else
#define COMPILER "unknown"
#endif
int main(void) { puts("c:" PROBE_ARCH); puts("compiler:" COMPILER); return 0; }
''')


def compile_and_run(label, folder, rust_command):
    system, arch, _ = TARGETS[label]
    env = windows_compiler_env(arch) if system == "Windows" else None
    suffix = ".exe" if system == "Windows" else ""
    rust_exe, c_exe = folder / ("rust-hello" + suffix), folder / ("c-hello" + suffix)
    run(rust_command + ["hello.rs", "-o", str(rust_exe)], cwd=folder, env=env)
    rust_output = run([str(rust_exe)], cwd=folder)
    if rust_output != "rust:" + arch:
        raise ProbeError("Executed Rust binary architecture mismatch")
    if system == "Windows":
        cl = shutil.which("cl.exe", path=env.get("PATH"))
        if not cl:
            raise ProbeError("Native MSVC compiler missing")
        run([cl, "/nologo", "/W4", "/WX", "hello.c", "/Fe:" + str(c_exe)], cwd=folder, env=env)
    else:
        cc = shutil.which("clang") if system == "Darwin" else shutil.which("cc")
        if not cc:
            raise ProbeError("Native C compiler missing")
        run([cc, "-Wall", "-Wextra", "-Werror", "hello.c", "-o", str(c_exe)], cwd=folder)
    c_output = run([str(c_exe)], cwd=folder)
    c_lines = c_output.splitlines()
    if len(c_lines) != 2 or c_lines[0] != "c:" + arch or not c_lines[1].startswith("compiler:"):
        raise ProbeError("Executed C binary architecture/compiler mismatch")
    return {"status": "passed", "rust_output": rust_output, "c_output": c_lines[0],
            "c_target_arch": arch, "c_compiler": c_lines[1][9:][:240]}


def metal_probe(folder):
    result = {"shader_compile": "not_run", "device": "not_tested",
              "gpu_execution": "not_tested"}
    (folder / "probe.metal").write_text('''#include <metal_stdlib>
using namespace metal;
kernel void probe(device float *out [[buffer(0)]], uint id [[thread_position_in_grid]]) {
    out[id] = float(id);
}
''')
    try:
        run(["xcrun", "-sdk", "macosx", "metal", "-c", "probe.metal", "-o", "probe.air"], cwd=folder)
        run(["xcrun", "-sdk", "macosx", "metallib", "probe.air", "-o", "probe.metallib"], cwd=folder)
        if not (folder / "probe.metallib").stat().st_size:
            raise ProbeError("Metal library is empty")
        result["shader_compile"] = "passed"
    except ProbeError as exc:
        result.update(shader_compile="failed", shader_error=str(exc))
    (folder / "device.m").write_text('''#import <Foundation/Foundation.h>
#import <Metal/Metal.h>
#include <stdio.h>
int main(void) { @autoreleasepool {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    puts(device ? "metal_device_available" : "metal_device_unavailable");
    return 0;
} }
''')
    try:
        run(["xcrun", "clang", "-fobjc-arc", "device.m", "-framework", "Foundation",
             "-framework", "Metal", "-o", "metal-device"], cwd=folder)
        output = run([str(folder / "metal-device")], cwd=folder)
        if output not in ("metal_device_available", "metal_device_unavailable"):
            raise ProbeError("Unrecognized Metal device result")
        result["device"] = "available" if output == "metal_device_available" else "unavailable"
    except ProbeError as exc:
        result.update(device="failed", device_error=str(exc))
    result["note"] = "Device discovery only; no GPU command buffer or rendering test executed."
    return result


def emit(result):
    encoded = json.dumps(result, indent=2, sort_keys=True)
    print(encoded)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("## Native feasibility probe\n\n```json\n" + encoded + "\n```\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runner", required=True, choices=TARGETS)
    parser.add_argument("--install-rust", action="store_true",
                        help="Allow rustup to install only the fixed native minimal toolchain")
    args = parser.parse_args(argv)
    result = {"schema_version": 1, "runner": args.runner, "status": "failed",
              "rust_version": RUST_VERSION, "expected_target": TARGETS[args.runner][2]}
    try:
        identity = machine_identity()
        result["machine"] = identity
        validate_native(args.runner, identity["os"], identity["native_arch"],
                        identity["process_arch"], identity["translated"])
        result["native_validation"] = "passed"
        rust_command, verbose = rust_tool(args.runner, args.install_rust)
        result["rust_host"] = rust_host(verbose)
        with tempfile.TemporaryDirectory(prefix="native-build-probe-") as directory:
            folder = Path(directory)
            fixture_sources(folder)
            result["hello"] = compile_and_run(args.runner, folder, rust_command)
            if identity["os"] == "Darwin":
                result["metal"] = metal_probe(folder)
                if result["metal"]["shader_compile"] != "passed" or result["metal"]["device"] == "failed":
                    raise ProbeError("Metal compiler/device probe failed; see metal results")
            else:
                result["metal"] = {"status": "not_applicable"}
        result["status"] = "passed"
    except ProbeError as exc:
        result["error"] = str(exc)
    emit(result)
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
