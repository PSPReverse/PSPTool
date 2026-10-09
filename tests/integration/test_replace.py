# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2026 contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest

from psptool import PSPTool
from psptool.header_file import HeaderFile

dirname = os.path.dirname(__file__)
rom_fixtures_path = os.path.join(dirname, "fixtures/roms")


class TestReplace(unittest.TestCase):
    # Cache PSPTool objects across tests in a class member
    cached_pts = {}

    def fixture_roms(self):
        for subdir, dirs, files in os.walk(rom_fixtures_path):
            for file in files:
                if file[0] == ".":
                    continue
                filename = os.path.join(subdir, file)
                yield filename

    def pt_from_file(self, filename) -> PSPTool:
        if filename not in self.__class__.cached_pts.keys():
            with io.StringIO() as stderr_buf:
                with contextlib.redirect_stderr(stderr_buf):
                    self.cached_pts[filename] = PSPTool.from_file(filename)
                warnings = stderr_buf.getvalue().split("\n")

        return self.__class__.cached_pts[filename]

    def find_substitutable_entry(self, pt: PSPTool):
        """Find the first unsigned HeaderFile entry that can be substituted without re-signing."""
        for r_i, rom in enumerate(pt.blob.roms):
            for d_i, d in enumerate(rom.directories):
                for f_i, file in enumerate(d.files):
                    if type(file) is HeaderFile and not getattr(
                        file, "is_signed", False
                    ):
                        return r_i, d_i, f_i, file
        return None

    def test_extract_and_substitute_cli(self):
        """Extract a file via CLI (-X) and reinsert/substitute it back (-R).
        The newly created ROM should be byte-for-byte identical to the original fixture.
        """
        repo_root = os.path.abspath(os.path.join(dirname, "../.."))
        env = dict(os.environ)
        env["PYTHONPATH"] = repo_root + (
            os.pathsep + env["PYTHONPATH"] if "PYTHONPATH" in env else ""
        )

        for filename in self.fixture_roms():
            with self.subTest(filename=filename):
                try:
                    pt = self.pt_from_file(filename)
                except Exception as e:
                    self.skipTest(f"Failed to parse ROM: {e}")

                target = self.find_substitutable_entry(pt)
                if not target:
                    self.skipTest("No substitutable unsigned HeaderFile found in ROM")

                r_i, d_i, f_i, file = target

                with tempfile.TemporaryDirectory() as td:
                    extracted_path = os.path.join(td, "extracted.bin")
                    new_rom_path = os.path.join(td, "new_rom.bin")

                    # 1. Extract file via CLI (-X)
                    cmd_extract = [
                        sys.executable,
                        "-m",
                        "psptool",
                        filename,
                        "-X",
                        "-r",
                        str(r_i),
                        "-d",
                        str(d_i),
                        "-e",
                        str(f_i),
                        "-o",
                        extracted_path,
                    ]
                    res_extract = subprocess.run(
                        cmd_extract, capture_output=True, text=True, env=env
                    )
                    self.assertEqual(
                        res_extract.returncode,
                        0,
                        f"CLI extract (-X) failed on {os.path.basename(filename)}:\n"
                        f"stdout: {res_extract.stdout}\nstderr: {res_extract.stderr}",
                    )
                    self.assertTrue(os.path.isfile(extracted_path))
                    self.assertGreater(os.path.getsize(extracted_path), 0)

                    # 2. Reinsert / substitute file back via CLI (-R)
                    cmd_replace = [
                        sys.executable,
                        "-m",
                        "psptool",
                        filename,
                        "-R",
                        "-r",
                        str(r_i),
                        "-d",
                        str(d_i),
                        "-e",
                        str(f_i),
                        "-s",
                        extracted_path,
                        "-o",
                        new_rom_path,
                    ]
                    res_replace = subprocess.run(
                        cmd_replace, capture_output=True, text=True, env=env
                    )
                    self.assertEqual(
                        res_replace.returncode,
                        0,
                        f"CLI replace (-R) failed on {os.path.basename(filename)}:\n"
                        f"stdout: {res_replace.stdout}\nstderr: {res_replace.stderr}",
                    )
                    self.assertTrue(os.path.isfile(new_rom_path))

                    # 3. Verify original fixture and newly created ROM are identical
                    with open(filename, "rb") as f_orig, open(
                        new_rom_path, "rb"
                    ) as f_new:
                        orig_bytes = f_orig.read()
                        new_bytes = f_new.read()

                    self.assertEqual(
                        len(orig_bytes),
                        len(new_bytes),
                        f"File size mismatch for {os.path.basename(filename)}: "
                        f"original is {len(orig_bytes)} bytes, new is {len(new_bytes)} bytes",
                    )
                    self.assertEqual(
                        orig_bytes,
                        new_bytes,
                        f"Content mismatch: newly created ROM differs from original fixture {os.path.basename(filename)}",
                    )


if __name__ == "__main__":
    unittest.main()
