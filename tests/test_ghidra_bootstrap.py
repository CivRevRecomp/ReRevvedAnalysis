from __future__ import annotations

import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
BOOTSTRAP = REPO / "tools" / "bootstrap-ghidra.ps1"
GHIDRA_DIR = REPO / "ghidra"


class GhidraBootstrapTests(unittest.TestCase):
    def run_bootstrap(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [
            shutil.which("pwsh") or shutil.which("powershell") or "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(BOOTSTRAP),
            *args,
        ]
        environment = os.environ.copy()
        environment["REREVVED_GHIDRA_PROJECTS"] = str(REPO / "canonical")
        environment["REREVVED_GHIDRA_PROJECT"] = "canonical"
        return subprocess.run(
            command,
            cwd=REPO,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def plan_args(
        self,
        project_dir: Path | None = None,
        project_name: str = "disposable",
    ) -> tuple[str, ...]:
        disposable = project_dir or (REPO / "disposable-plan")
        return (
            "-Plan",
            "-DisposableProjectDir",
            str(disposable),
            "-DisposableProjectName",
            project_name,
            "-Out",
            str(REPO / "tests" / "plan-result.json"),
            "-LogPath",
            str(REPO / "tests" / "plan-headless.log"),
            "-CanonicalProjectDir",
            str(REPO / "canonical"),
            "-CanonicalProjectName",
            "canonical",
        )

    def test_plan_preserves_repair_order_without_writing(self):
        result = self.run_bootstrap(*self.plan_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["Mode"], "Plan")
        self.assertEqual(
            plan["Scripts"],
            [
                "FixXenonThunks.java",
                "RebuildTruncatedFunctions.java",
                "RecoverSplitConstRefs.java",
            ],
        )
        self.assertFalse((REPO / "tests" / "plan-result.json").exists())
        self.assertFalse((REPO / "tests" / "plan-headless.log").exists())

    def test_plan_refuses_configured_canonical_project(self):
        result = self.run_bootstrap(
            *self.plan_args(
                project_dir=REPO / "canonical", project_name="canonical"
            )
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("configured canonical project", result.stderr)

    def test_plan_prepends_generated_function_seed(self):
        function_map = REPO / "tests" / "generated-init.cpp"
        result = self.run_bootstrap(
            *self.plan_args(),
            "-FunctionMap",
            str(function_map),
            "-CodeSeedSites",
            "0x8269CAE0,0x8269CAE4",
            "-ConstRefAcceptTarget",
            "0x821B15C0",
            "-ConstRefAcceptSites",
            "0x82DAB144,0x82DAB14C,0x82DAB154",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["Scripts"][2], "SeedGeneratedFunctions.java")
        self.assertEqual(plan["FunctionMap"], str(function_map.resolve()))
        self.assertEqual(plan["CodeSeedSites"], "0x8269CAE0,0x8269CAE4")
        self.assertEqual(plan["ConstRefAcceptTarget"], "0x821B15C0")
        self.assertEqual(
            plan["ConstRefAcceptSites"],
            "0x82DAB144,0x82DAB14C,0x82DAB154",
        )

    def test_disposable_project_must_be_explicit(self):
        result = self.run_bootstrap(
            "-Plan",
            "-DisposableProjectName",
            "disposable",
            "-Out",
            str(REPO / "tests" / "missing-project-result.json"),
            "-LogPath",
            str(REPO / "tests" / "missing-project.log"),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Disposable project directory is required", result.stderr)

    def test_code_seeds_require_function_map(self):
        result = self.run_bootstrap(
            *self.plan_args(), "-CodeSeedSites", "0x8269CAE0"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require a generated function map", result.stderr)

    def test_constref_acceptance_requires_target_and_sites(self):
        result = self.run_bootstrap(
            *self.plan_args(), "-ConstRefAcceptTarget", "0x821B15C0"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires both target and sites", result.stderr)

    def test_index_covers_every_java_script(self):
        readme = (GHIDRA_DIR / "README.md").read_text(encoding="utf-8")
        scripts = sorted(path.name for path in GHIDRA_DIR.glob("*.java"))
        self.assertEqual(len(scripts), 18)
        for script in scripts:
            self.assertIn(f"`{script}`", readme)

    def test_execution_log_is_written_as_utf8(self):
        script = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("$stepOutput = @(& $headless @headlessArgs 2>&1)", script)
        self.assertIn(
            "Add-Content -LiteralPath $LogPath -Encoding UTF8", script
        )
        self.assertIn(".Replace([string][char]0, '')", script)
        self.assertNotIn(">> $LogPath", script)


if __name__ == "__main__":
    unittest.main()
