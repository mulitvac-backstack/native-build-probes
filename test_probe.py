"""Local contract checks. Hosted compiler execution remains separate evidence."""
import contextlib
import io
import unittest
from unittest.mock import patch
import probe


class ArchitectureTests(unittest.TestCase):
    def test_aliases(self):
        for alias in ("AMD64", "x64", "x86_64"):
            self.assertEqual(probe.normalize_arch(alias), "x86_64")
        for alias in ("ARM64", "aarch64"):
            self.assertEqual(probe.normalize_arch(alias), "aarch64")
        for alias in ("i386", "armv7l", "", "ppc64"):
            with self.assertRaises(probe.ProbeError):
                probe.normalize_arch(alias)

    def test_all_six_native_combinations(self):
        self.assertEqual(len(probe.TARGETS), 6)
        for label, (system, arch, target) in probe.TARGETS.items():
            with self.subTest(label=label):
                probe.validate_native(label, system, arch, arch)
                self.assertEqual(probe.validate_rust(label, "release: 1.98.1\nhost: " + target), target)

    def test_wrong_os_hardware_process_or_rosetta_rejected(self):
        cases = [("Other", "x86_64", "x86_64", False),
                 ("Darwin", "aarch64", "x86_64", False),
                 ("Darwin", "x86_64", "aarch64", False),
                 ("Darwin", "x86_64", "x86_64", True)]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(probe.ProbeError):
                probe.validate_native("macos-15-intel", *args)
        with self.assertRaises(probe.ProbeError):
            probe.validate_native("windows-2025", "Windows", "ARM64", "AMD64", True)

    def test_cross_rust_target_or_release_rejected(self):
        for verbose in ("host: aarch64-unknown-linux-gnu\nrelease: 1.98.1",
                        "host: x86_64-unknown-linux-gnu\nrelease: 1.98.0",
                        "release: 1.98.1", "host: x\nhost: y\nrelease: 1.98.1"):
            with self.subTest(verbose=verbose), self.assertRaises(probe.ProbeError):
                probe.validate_rust("ubuntu-24.04", verbose)

    def test_mismatch_fails_before_toolchain_or_compilation(self):
        identity = dict(os="Windows", native_arch="aarch64", process_arch="x86_64", translated=True)
        output = io.StringIO()
        with patch.object(probe, "machine_identity", return_value=identity), \
             patch.object(probe, "rust_tool") as tool, \
             patch.dict(probe.os.environ, {}, clear=True), contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(["--runner", "windows-2025"]), 1)
        tool.assert_not_called()
        self.assertIn('"status": "failed"', output.getvalue())
        self.assertNotIn('"hello"', output.getvalue())

    def test_metal_unavailable_is_not_gpu_execution_or_compiler_failure(self):
        from pathlib import Path
        import tempfile
        def command(args, cwd=None, **_):
            if "metallib" in args:
                (cwd / "probe.metallib").write_bytes(b"fixture")
            return "metal_device_unavailable" if str(args[0]).endswith("metal-device") else ""
        with tempfile.TemporaryDirectory() as directory, patch.object(probe, "run", side_effect=command):
            result = probe.metal_probe(Path(directory))
        self.assertEqual(result["shader_compile"], "passed")
        self.assertEqual(result["device"], "unavailable")
        self.assertEqual(result["gpu_execution"], "not_tested")


    def test_metal_tool_failure_remains_failure_when_device_unavailable(self):
        from pathlib import Path
        import tempfile
        def command(args, **_):
            if "metal" in args:
                raise probe.ProbeError("Metal compiler unavailable")
            return "metal_device_unavailable" if str(args[0]).endswith("metal-device") else ""
        with tempfile.TemporaryDirectory() as directory, patch.object(probe, "run", side_effect=command):
            result = probe.metal_probe(Path(directory))
        self.assertEqual(result["shader_compile"], "failed")
        self.assertEqual(result["device"], "unavailable")
        self.assertEqual(result["gpu_execution"], "not_tested")

    def test_summary_does_not_dump_environment(self):
        import json
        identity = dict(os="Linux", native_arch="aarch64", process_arch="aarch64", translated=False)
        output = io.StringIO()
        with patch.object(probe, "machine_identity", return_value=identity), \
             patch.dict(probe.os.environ, {"DO_NOT_EMIT": "private-sentinel"}, clear=True), \
             contextlib.redirect_stdout(output):
            self.assertEqual(probe.main(["--runner", "ubuntu-24.04"]), 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")
        self.assertNotIn("private-sentinel", output.getvalue())
        self.assertNotIn("DO_NOT_EMIT", output.getvalue())


    def test_windows_batch_path_uses_raw_cmd_quotes_and_only_imports_compiler_env(self):
        from pathlib import Path
        from subprocess import CompletedProcess
        calls = []
        installation = r"C:\Program Files\Microsoft Visual Studio\18\Enterprise"
        def command(args, **kwargs):
            calls.append((args, kwargs))
            if isinstance(args, list):
                return CompletedProcess(args, 0, installation + "\n", "")
            return CompletedProcess(args, 0,
                "Path=native-tools\nINCLUDE=headers\nLIB=libraries\nLIBPATH=metadata\n"
                "PRIVATE_NEW_VALUE=not-imported\nORIGINAL=not-overwritten\n", "")
        for arch, target in (("aarch64", "arm64"), ("x86_64", "x64")):
            calls.clear()
            with self.subTest(arch=arch), patch.object(Path, "is_file", return_value=True), \
                 patch.object(probe.subprocess, "run", side_effect=command), \
                 patch.dict(probe.os.environ, {"ORIGINAL": "preserved"}, clear=True):
                result = probe.windows_compiler_env(arch)
            raw, options = calls[1]
            self.assertIsInstance(raw, str)
            self.assertTrue(raw.startswith('cmd.exe /d /s /c "call "'))
            self.assertTrue(raw.endswith(' >nul && set"'))
            self.assertIn(installation, raw)
            self.assertIn('VsDevCmd.bat" -no_logo -arch=' + target, raw)
            self.assertIn(' -host_arch=' + target, raw)
            self.assertNotIn('\\"', raw)
            self.assertIs(options["shell"], False)
            self.assertEqual(result, {"ORIGINAL": "preserved", "PATH": "native-tools",
                "INCLUDE": "headers", "LIB": "libraries", "LIBPATH": "metadata"})

    def test_raw_cmd_failure_remains_bounded_and_named(self):
        from subprocess import CompletedProcess
        with patch.object(probe.subprocess, "run", return_value=CompletedProcess(
                "cmd.exe", 1, "", "x" * 5000)):
            with self.assertRaises(probe.ProbeError) as failure:
                probe.run('cmd.exe /d /s /c "fixed"')
        self.assertTrue(str(failure.exception).startswith("cmd.exe failed: "))
        self.assertLess(len(str(failure.exception)), 1700)


    def test_intel_mac_missing_arm_oid_requires_positive_vendor(self):
        def command(args, **_):
            name = args[-1]
            if name == "hw.optional.arm64":
                raise probe.ProbeError("sysctl failed: sysctl: unknown oid 'hw.optional.arm64'")
            if name == "sysctl.proc_translated":
                raise probe.ProbeError("sysctl failed: sysctl: unknown oid 'sysctl.proc_translated'")
            return "GenuineIntel"
        with patch.object(probe.platform, "system", return_value="Darwin"), \
             patch.object(probe.platform, "machine", return_value="x86_64"), \
             patch.object(probe, "run", side_effect=command):
            identity = probe.machine_identity()
        probe.validate_native("macos-15-intel", identity["os"], identity["native_arch"],
                              identity["process_arch"], identity["translated"])
        self.assertEqual(identity["native_arch"], "x86_64")
        self.assertFalse(identity["translated"])

    def test_intel_fallback_rejects_unknown_vendor_query_errors_and_rosetta(self):
        for vendor, translation, arm_error in (
                ("Unknown", None, "unknown oid 'hw.optional.arm64'"),
                ("GenuineIntel", "1", "unknown oid 'hw.optional.arm64'"),
                (probe.ProbeError("vendor query failed"), None, "unknown oid 'hw.optional.arm64'"),
                ("GenuineIntel", None, "permission denied")):
            def command(args, **_):
                if args[-1] == "hw.optional.arm64":
                    raise probe.ProbeError("sysctl failed: " + arm_error)
                if args[-1] == "sysctl.proc_translated":
                    if translation is None:
                        raise probe.ProbeError("sysctl: unknown oid 'sysctl.proc_translated'")
                    return translation
                if isinstance(vendor, Exception):
                    raise vendor
                return vendor
            with self.subTest(vendor=str(vendor), translation=translation, error=arm_error), \
                 patch.object(probe.platform, "system", return_value="Darwin"), \
                 patch.object(probe.platform, "machine", return_value="x86_64"), \
                 patch.object(probe, "run", side_effect=command), self.assertRaises(probe.ProbeError):
                probe.machine_identity()

    def test_rosetta_on_apple_silicon_cannot_pass_intel_row(self):
        def command(args, **_):
            return "1"  # Apple Silicon hardware, translated x86_64 process.
        with patch.object(probe.platform, "system", return_value="Darwin"), \
             patch.object(probe.platform, "machine", return_value="x86_64"), \
             patch.object(probe, "run", side_effect=command):
            identity = probe.machine_identity()
        with self.assertRaises(probe.ProbeError):
            probe.validate_native("macos-15-intel", identity["os"], identity["native_arch"],
                                  identity["process_arch"], identity["translated"])


if __name__ == "__main__":
    unittest.main()
