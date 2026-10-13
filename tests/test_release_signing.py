#!/usr/bin/env python3
"""Check release signing policy against real macOS code signatures."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts/build-release-dmgs.sh"


@unittest.skipUnless(shutil.which("clang") and shutil.which("codesign"),
                     "requires macOS compiler and signing tools")
class ReleaseSigningTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="mace-signing-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.app = self.root / "SigningFixture.app"
        self.binary = self.app / "Contents/MacOS/SigningFixture"
        self.binary.parent.mkdir(parents=True)
        (self.app / "Contents/Info.plist").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"https://www.apple.com/DTDs/PropertyList-1.0.dtd">'
            '<plist version="1.0"><dict>'
            '<key>CFBundleIdentifier</key><string>org.example.signingfixture</string>'
            '<key>CFBundleExecutable</key><string>SigningFixture</string>'
            '<key>CFBundlePackageType</key><string>APPL</string>'
            '</dict></plist>'
        )
        source = self.root / "main.c"
        source.write_text("int main(void) { return 0; }\n")
        subprocess.run(["clang", str(source), "-o", str(self.binary)],
                       check=True, capture_output=True)
        self.env = dict(os.environ)
        for key in ("CODE_SIGN_IDENTITY", "DEVELOPMENT_TEAM", "NOTARY_PROFILE",
                    "REQUIRE_NOTARIZATION"):
            self.env.pop(key, None)
        self.env["ARTIFACT_DIR"] = str(self.root / "artifacts")

    def sign(self, runtime=False):
        command = ["codesign", "--force", "--sign", "-"]
        if runtime:
            command += ["--options", "runtime"]
        subprocess.run(command + [str(self.app)], check=True, capture_output=True)

    def verify(self):
        return subprocess.run(
            ["bash", "-c", 'source "$1"; verify_app_signing "$2"',
             "signing-test", str(BUILD_SCRIPT), str(self.app)],
            env=self.env, capture_output=True, text=True,
        )

    def test_ad_hoc_app_without_hardened_runtime_is_accepted(self):
        self.sign()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_ad_hoc_app_with_hardened_runtime_is_rejected(self):
        self.sign(runtime=True)
        # Signature integrity alone passes for the broken release configuration.
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(self.app)],
                       check=True, capture_output=True)
        result = self.verify()
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertIn("ad-hoc app still enables hardened runtime", result.stderr)

    def test_embedded_ad_hoc_library_loads(self):
        dependency_root = self.root / "deps"
        library = dependency_root / "lib/libre2.11.dylib"
        library.parent.mkdir(parents=True)
        library_source = self.root / "library.c"
        library_source.write_text("int fixture_value(void) { return 73; }\n")
        subprocess.run(["clang", "-dynamiclib", str(library_source),
                        "-o", str(library), "-Wl,-headerpad_max_install_names"],
                       check=True, capture_output=True)
        executable_source = self.root / "main.c"
        executable_source.write_text(
            '#include <stdio.h>\nint fixture_value(void);\n'
            'int main(void) { printf("%d\\n", fixture_value()); return 0; }\n'
        )
        subprocess.run(["clang", str(executable_source), str(library),
                        "-o", str(self.binary), "-Wl,-headerpad_max_install_names",
                        "-Wl,-rpath,@executable_path/../Frameworks"],
                       check=True, capture_output=True)
        env = dict(self.env, RE2_DEPENDENCY_ROOT=str(dependency_root),
                   EXPANDED_CODE_SIGN_IDENTITY="-", SRCROOT=str(self.root))
        subprocess.run(["bash", str(ROOT / "scripts/embed-homebrew-dylibs.sh"),
                        str(self.app), "SigningFixture"],
                       env=env, check=True, capture_output=True)
        self.sign()
        result = self.verify()
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([str(self.binary)], check=True,
                                capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "73")

    def test_modified_executable_is_rejected(self):
        self.sign()
        data = bytearray(self.binary.read_bytes())
        data[0] ^= 1
        self.binary.write_bytes(data)
        result = self.verify()
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
