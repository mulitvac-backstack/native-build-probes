"""Offline contract tests; no network, process-global environment edits or builds."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "headspace_source_build", Path(__file__).parent / "scripts/headspace_source_build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class SourceBuildTests(unittest.TestCase):
    def fixture(self, root, path, text):
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")

    def test_revision_is_immutable_hex_only(self):
        self.assertEqual(build.validate_revision("AB" * 20), "ab" * 20)
        for invalid in ("main", "a" * 39, "a" * 41, "a" * 40 + "\n", "$(whoami)",
                        "--upload", "https://another.invalid/repo", None):
            with self.subTest(invalid=invalid), self.assertRaises(build.BuildFailure) as failure:
                build.validate_revision(invalid)
            self.assertEqual(failure.exception.code, "invalid_revision")

    def test_contained_workspace_and_target_dependencies_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root, "Cargo.toml", '''[workspace]
members = ["core", "app"]
[workspace.dependencies]
core = { path = "core" }
[patch.crates-io]
helper = { path = "core" }
''')
            self.fixture(root, "core/Cargo.toml", '[package]\nname="core"\nversion="0.1.0"\n')
            self.fixture(root, "app/Cargo.toml", '''[package]
name = "app"
version = "0.1.0"
[dependencies]
core = { path = "../core" }
[target.'cfg(windows)'.build-dependencies]
core = { path = "../core" }
[package.metadata]
path = "not-a-dependency"
''')
            result = build.preflight(root)
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["manifests_checked"], 3)

    def test_absolute_missing_and_escaping_paths_are_distinct_blockers(self):
        paths = (("/home/person/private/bloom", "absolute_dependency_path"),
                 ("/", "absolute_dependency_path"),
                 ("//private/SDK", "absolute_dependency_path"),
                 (r"C:\private\bloom", "absolute_dependency_path"),
                 ("C:/private/bloom", "absolute_dependency_path"),
                 ("C:private", "absolute_dependency_path"),
                 (r"\private\bloom", "absolute_dependency_path"),
                 (r"\\server\private", "absolute_dependency_path"),
                 ("../external", "dependency_outside_source"),
                 (r"..\external", "dependency_outside_source"),
                 ("missing", "missing_path_dependency"))
        for value, expected in paths:
            with self.subTest(path=value), tempfile.TemporaryDirectory() as directory:
                # The classifier uses both pure path grammars, rather than the
                # host Path.is_absolute which differs on Windows vs POSIX.
                self.assertEqual(build.absolute_dependency_path(value),
                                 expected == "absolute_dependency_path")
                root = Path(directory)
                # JSON strings are also valid TOML basic strings for these paths.
                self.fixture(root, "Cargo.toml", '[dependencies]\nbloom = { path = ' + json.dumps(value) + ' }\n')
                result = build.preflight(root)
                self.assertEqual(result["finding_count"], 1)
                self.assertEqual(result["findings"][0]["code"], expected)
                self.assertEqual(result["findings"][0]["dependency"], "dependencies.bloom")

    def test_symlink_escape_cannot_satisfy_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "source"
            root.mkdir()
            self.fixture(parent, "outside/Cargo.toml", '[package]\nname="external"\n')
            try:
                (root / "linked").symlink_to(parent / "outside", target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Runner cannot create symlinks without elevation")
            self.fixture(root, "Cargo.toml", '[dependencies]\nbloom = { path = "linked" }\n')
            result = build.preflight(root)
            self.assertEqual(result["findings"][0]["code"], "dependency_outside_source")
            self.assertEqual(result["manifests_checked"], 1)

    def test_symlinked_manifest_outside_is_never_read(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "source"
            root.mkdir()
            self.fixture(parent, "outside.toml", "not valid TOML (must never be parsed)")
            try:
                (root / "Cargo.toml").symlink_to(parent / "outside.toml")
            except (OSError, NotImplementedError):
                self.skipTest("Runner cannot create symlinks without elevation")
            result = build.preflight(root)
        self.assertEqual(result["findings"][0]["code"], "manifest_outside_source")

    def test_malformed_manifest_and_large_findings_stay_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entries = "\n".join('dep' + str(i) + '={path="missing"}' for i in range(50))
            self.fixture(root, "Cargo.toml", "[dependencies]\n" + entries)
            self.fixture(root, "broken/Cargo.toml", "invalid [ TOML")
            result = build.preflight(root)
        self.assertEqual(result["finding_count"], 51)
        self.assertEqual(len(result["findings"]), build.MAX_FINDINGS)
        self.assertEqual(result["omitted_findings"], 31)

    def test_fetch_uses_only_fixed_public_repository_and_verifies_head(self):
        revision = "a" * 40
        calls = []
        def execute(command, phase, **options):
            calls.append((command, phase, options))
            return revision if command[-2:] == ["rev-parse", "HEAD"] else ""
        build.fetch_source(Path("controlled-fixture"), revision, execute)
        self.assertEqual(len(calls), 5)
        self.assertTrue(any(build.SOURCE_URL in command for command, _, _ in calls))
        self.assertTrue(any(command[-4:] == ["fetch", "--depth=1", "origin", revision]
                            for command, _, _ in calls))
        self.assertTrue(all(options["env"]["GIT_TERMINAL_PROMPT"] == "0"
                            for _, _, options in calls))
        with self.assertRaises(build.BuildFailure) as failure:
            build.fetch_source(Path("controlled-fixture"), revision, lambda *args, **kwargs: "b" * 40)
        self.assertEqual(failure.exception.code, "source_revision_mismatch")

    def test_no_recipe_is_explicit_failure_and_never_successfully_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            formats = {"deb": "not_run", "rpm": "not_run"}
            with self.assertRaises(build.BuildFailure) as failure:
                build.package(Path(directory), "aarch64-unknown-linux-gnu", formats)
        self.assertEqual(failure.exception.code, "package_recipe_missing")
        self.assertEqual(set(formats.values()), {"not_run"})

    def test_all_required_format_recipes_run_and_partial_failure_remains_visible(self):
        for system, formats_required in build.FORMATS.items():
            with self.subTest(system=system), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.fixture(root, build.RECIPE, "# controlled fixture recipe\n")
                calls = []
                formats = dict.fromkeys(formats_required, "not_run")
                build.package(root, "fixed-target", formats,
                              execute=lambda command, phase, **kwargs: calls.append((command, phase)))
                self.assertEqual([command[-1] for command, _ in calls], list(formats_required))
                self.assertTrue(all(command[:2] == [sys.executable, str(root / build.RECIPE)]
                                    and command[2:5] == ["--target", "fixed-target", "--format"]
                                    for command, _ in calls))
                self.assertEqual(set(formats.values()), {"recipe_completed_artifacts_not_qualified"})
                formats = dict.fromkeys(formats_required, "not_run")
                def fail_second(command, phase, **_):
                    if command[-1] == formats_required[1]:
                        raise build.BuildFailure(phase + "_failed", "Controlled fixture failure")
                with self.assertRaises(build.BuildFailure):
                    build.package(root, "fixed-target", formats, execute=fail_second)
                self.assertEqual(formats[formats_required[0]], "recipe_completed_artifacts_not_qualified")
                self.assertEqual(formats[formats_required[1]], "failed")

    def test_command_failure_timeout_and_missing_executable_are_classified(self):
        cases = (([sys.executable, "-c", "raise SystemExit(7)"], "cargo_test_failed", 5),
                 ([sys.executable, "-c", "import time; time.sleep(10)"], "cargo_test_timeout", 0.1),
                 (["headspace-nonexistent-fixture-command"], "cargo_test_unavailable", 5))
        for command, expected, timeout in cases:
            with self.subTest(expected=expected), self.assertRaises(build.BuildFailure) as failure:
                build.run(command, "cargo_test", timeout=timeout)
            self.assertEqual(failure.exception.code, expected)

    def test_current_bloom_blocker_stops_before_toolchain_and_cargo(self):
        identity = dict(os="Linux", native_arch="aarch64", process_arch="aarch64", translated=False)
        def fetch(source, revision):
            source.mkdir()
            self.fixture(source, "Cargo.toml", '[dependencies]\nbloomdb={path="/private/SDK"}\n')
        summaries = []
        with patch.object(build.probe, "machine_identity", return_value=identity), \
             patch.object(build, "fetch_source", side_effect=fetch), \
             patch.object(build.probe, "rust_tool") as toolchain, \
             patch.object(build, "run") as command, \
             patch.object(build, "emit", side_effect=lambda result, *_: summaries.append(result)):
            code = build.main(["--runner", "ubuntu-24.04-arm", "--revision", "a" * 40])
        self.assertEqual(code, 1)
        toolchain.assert_not_called()
        command.assert_not_called()
        result = summaries[0]
        self.assertEqual(result["phase"], "preflight")
        self.assertEqual(result["blocker"]["code"], "nonportable_source_dependencies")
        self.assertEqual(result["verified_source_revision"], "a" * 40)
        self.assertEqual(set(result["formats"].values()), {"not_run"})
        self.assertNotIn("cargo_test", result)

    def test_portable_source_runs_real_test_build_then_package(self):
        identity = dict(os="Linux", native_arch="aarch64", process_arch="aarch64", translated=False)
        calls, summaries = [], []
        def fetch(source, revision):
            source.mkdir()
            self.fixture(source, "Cargo.toml", '[workspace]\nmembers=[]\n')
            self.fixture(source, build.RECIPE, "# fixture")
        def command(args, phase, **kwargs):
            calls.append((args, phase))
            return ""
        with patch.object(build.probe, "machine_identity", return_value=identity), \
             patch.object(build, "fetch_source", side_effect=fetch), \
             patch.object(build.probe, "rust_tool", return_value=(["rustup", "run", "fixed", "rustc"],
                 "host: aarch64-unknown-linux-gnu\nrelease: 1.98.1")), \
             patch.object(build, "run", side_effect=command), \
             patch.object(build, "package") as package, \
             patch.object(build, "emit", side_effect=lambda result, *_: summaries.append(result)):
            code = build.main(["--runner", "ubuntu-24.04-arm", "--revision", "a" * 40])
        self.assertEqual(code, 0)
        self.assertEqual([phase for _, phase in calls], ["cargo_test", "cargo_build"])
        self.assertIn("--locked", calls[0][0])
        self.assertNotIn("--release", calls[0][0])
        self.assertIn("--release", calls[1][0])
        self.assertEqual(calls[0][0][:5], ["rustup", "run", "fixed", "cargo", "test"])
        package.assert_called_once()
        self.assertEqual(summaries[0]["status"], "passed")
        self.assertEqual(summaries[0]["runtime_install_signing_publication"], "not_tested")

    def test_bad_revision_and_native_mismatch_fail_before_public_fetch(self):
        identity = dict(os="Linux", native_arch="aarch64", process_arch="aarch64", translated=False)
        for revision, runner, phase in (("main", "ubuntu-24.04-arm", "input"),
                                         ("a" * 40, "ubuntu-24.04", "native_identity")):
            reports = []
            with self.subTest(phase=phase), \
                 patch.object(build.probe, "machine_identity", return_value=identity), \
                 patch.object(build, "fetch_source") as fetch, \
                 patch.object(build, "emit", side_effect=lambda result, *_: reports.append(result)):
                self.assertEqual(build.main(["--runner", runner, "--revision", revision]), 1)
            fetch.assert_not_called()
            self.assertEqual(reports[0]["phase"], phase)

    def test_reports_have_bounded_json_and_do_not_include_process_environment(self):
        report = {"status": "failed", "source_revision": "a" * 40,
                  "preflight": {"findings": [{"detail": "x" * 1000}] * 30}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            build.emit(report)
        self.assertLess(len(output.getvalue().encode()), 16384)
        result = json.loads(output.getvalue())
        self.assertTrue(result["preflight"]["details_omitted"])
        self.assertNotIn("env", result)


if __name__ == "__main__":
    unittest.main()
