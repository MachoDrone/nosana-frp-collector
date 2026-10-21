"""Exercise the public Bash entry point without network or Docker access."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
TOOLS = {name: shutil.which(name) for name in ("mktemp", "rm")}


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="launcher-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.temp = self.root / "temporary files"
        self.temp.mkdir()
        self.work = self.root / "report destination"
        self.work.mkdir()
        self.payload = self.root / "payload.py"
        self.called = self.root / "downloads.jsonl"
        self.marker = self.root / "executed"
        for name, path in TOOLS.items():
            self.assertIsNotNone(path, name + " is needed to run launcher tests")
            (self.bin / name).symlink_to(path)
        (self.bin / "python3").symlink_to(sys.executable)
        self.env = dict(os.environ, PATH=str(self.bin), TMPDIR=str(self.temp),
                        TEST_PAYLOAD=str(self.payload), TEST_DOWNLOADS=str(self.called),
                        TEST_MARKER=str(self.marker))
        self.env.pop("BASH_ENV", None)
        self.mock_downloader("curl")

    def mock_downloader(self, name):
        script = self.bin / name
        script.write_text("#!%s\n" % sys.executable + '''
import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["TEST_DOWNLOADS"], "a") as output:
    output.write(json.dumps({"name": pathlib.Path(sys.argv[0]).name, "args": args}) + "\\n")
if os.environ.get("TEST_DOWNLOAD_EXIT"):
    sys.exit(int(os.environ["TEST_DOWNLOAD_EXIT"]))
if "--output" in args:
    target = args[args.index("--output") + 1]
else:
    target = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output-document="))
pathlib.Path(target).write_bytes(pathlib.Path(os.environ["TEST_PAYLOAD"]).read_bytes())
''')
        script.chmod(0o700)

    def run_launcher(self, original=None, served=None, args=()):
        if original is None:
            original = (PROJECT / "collector.py").read_bytes()
        self.payload.write_bytes(original if served is None else served)
        source = (PROJECT / "start.sh").read_text()
        digest = hashlib.sha256(original).hexdigest()
        source, replacements = re.subn(
            r"COLLECTOR_SHA256='[^']+'",
            "COLLECTOR_SHA256='%s'" % digest, source)
        self.assertEqual(replacements, 1)
        # Bash receives the launcher on stdin, as with curl/wget | bash.
        return subprocess.run([BASH, "-s", "--", *args], input=source,
                              text=True, capture_output=True, cwd=self.work,
                              env=self.env, timeout=15)

    def assert_clean(self):
        self.assertEqual(list(self.temp.iterdir()), [], "temporary download leaked")

    def marker_payload(self, exit_status=0):
        return ("import os, pathlib, sys\n"
                "pathlib.Path(os.environ['TEST_MARKER']).write_text('executed')\n"
                "sys.exit(%d)\n" % exit_status).encode()

    def test_actual_collector_help_works_through_pipe(self):
        result = self.run_launcher(args=("--help",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--logs-only", result.stdout)
        self.assertIn("--output-dir", result.stdout)
        self.assert_clean()

    def test_actual_collector_version_works_through_pipe(self):
        result = self.run_launcher(args=("--version",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0.1.0", result.stdout)
        self.assert_clean()

    def test_corrupted_payload_is_never_executed(self):
        original = self.marker_payload()
        result = self.run_launcher(original, original + b"# changed\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 verification failed", result.stderr)
        self.assertFalse(self.marker.exists())
        self.assert_clean()

    def test_truncated_payload_is_never_executed(self):
        original = self.marker_payload()
        result = self.run_launcher(original, original[:-4])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 verification failed", result.stderr)
        self.assertFalse(self.marker.exists())
        self.assert_clean()

    def test_download_failure_preserves_exit_and_cleans_up(self):
        self.env["TEST_DOWNLOAD_EXIT"] = "22"
        result = self.run_launcher(self.marker_payload())
        self.assertEqual(result.returncode, 22)
        self.assertIn("download failed", result.stderr)
        self.assertFalse(self.marker.exists())
        self.assert_clean()

    def test_collector_failure_preserves_exit_and_cleans_up(self):
        result = self.run_launcher(self.marker_payload(exit_status=37))
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertTrue(self.marker.exists())
        self.assert_clean()

    def test_no_downloader_has_clear_error(self):
        (self.bin / "curl").unlink()
        result = self.run_launcher(self.marker_payload())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("curl or wget is required", result.stderr)
        self.assertFalse(self.called.exists())
        self.assertFalse(self.marker.exists())
        self.assert_clean()

    def test_no_python_has_clear_error(self):
        (self.bin / "python3").unlink()
        result = self.run_launcher(self.marker_payload())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Python 3.8 or newer is required", result.stderr)
        self.assertFalse(self.called.exists())
        self.assert_clean()

    def test_wget_fallback(self):
        (self.bin / "curl").unlink()
        self.mock_downloader("wget")
        result = self.run_launcher(self.marker_payload())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.marker.exists())
        download = json.loads(self.called.read_text())
        self.assertEqual(download["name"], "wget")
        self.assertIn("--https-only", download["args"])
        self.assertTrue(download["args"][-1].endswith("/v0.1.0/collector.py"))
        self.assert_clean()

    def test_arguments_cwd_and_private_permissions_are_preserved(self):
        payload = b'''import json, os, pathlib, stat, sys
print(json.dumps({"args": sys.argv[1:], "cwd": os.getcwd(),
                  "mode": stat.S_IMODE(pathlib.Path(__file__).parent.stat().st_mode)}))
'''
        args = ("--container", "podman", "--output-dir", "a directory with spaces", "--logs-only")
        result = self.run_launcher(payload, args=args)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed["args"], list(args))
        self.assertEqual(observed["cwd"], str(self.work))
        self.assertEqual(observed["mode"], 0o700)
        download = json.loads(self.called.read_text())
        self.assertIn("--proto", download["args"])
        self.assertIn("--proto-redir", download["args"])
        self.assertIn("=https", download["args"])
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
