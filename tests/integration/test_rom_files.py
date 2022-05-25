import unittest
import os
import psptool
import io
import contextlib

from psptool.entry import HeaderEntry

rom_fixtures_path = 'tests/integration/fixtures/roms'


class TestRomFiles(unittest.TestCase):
    # We'll cache PSPTool objects across tests in a class member
    cached_pts = {}

    def fixture_roms(self):
        for subdir, dirs, files in os.walk(rom_fixtures_path):
            for file in files:
                if file[0] == '.':
                    continue
                filename = os.path.join(subdir, file)
                yield filename

    def pt_from_file(self, filename):
        if filename not in self.__class__.cached_pts.keys():
            with io.StringIO() as stderr_buf:
                with contextlib.redirect_stderr(stderr_buf):
                    self.cached_pts[filename] = psptool.PSPTool.from_file(filename)
                warnings = stderr_buf.getvalue().split('\n')

        return self.__class__.cached_pts[filename]

    def test_0_from_file(self):
        for filename in self.fixture_roms():
            with self.subTest(filename):
                pt = self.pt_from_file(filename)
                self.assertTrue(len(pt.blob.roms) > 0, "Did not find a single ROM")

    def test_to_file(self):
        for filename in self.fixture_roms():
            pt = self.pt_from_file(filename)
            with self.subTest(filename):
                pt.to_file('/dev/null')

    def test_ls(self):
        for filename in self.fixture_roms():
            pt = self.pt_from_file(filename)
            with self.subTest(filename):
                with io.StringIO() as stdout_buf:
                    with contextlib.redirect_stdout(stdout_buf):
                        with io.StringIO() as stderr_buf:
                            with contextlib.redirect_stderr(stderr_buf):
                                pt.ls()
                                pt.ls(verbose=True)
                                pt.ls_json()

    def test_extract_basic(self):
        for filename in self.fixture_roms():
            pt = self.pt_from_file(filename)
            roms = pt.blob.roms
            for rom_index, rom in enumerate(roms):
                directories = rom.directories
                for dir_index, directory in enumerate(directories):
                    for entry_index, entry in enumerate(directory.entries):
                        with self.subTest(f"{filename=}, path={rom_index}.{dir_index}.{entry_index}, type={entry.type}"):
                            out_bytes = entry.get_bytes()
                            self.assertEqual(len(out_bytes), entry.buffer_size)

    def test_extract_advanced(self):
        for filename in self.fixture_roms():
            pt = self.pt_from_file(filename)
            roms = pt.blob.roms
            for rom_index, rom in enumerate(roms):
                directories = rom.directories
                for dir_index, directory in enumerate(directories):
                    for entry_index, entry in enumerate(directory.entries):
                        with self.subTest(f"{filename=}, path={rom_index}.{dir_index}.{entry_index}, type={entry.type}"):
                            if isinstance(entry, HeaderEntry):
                                with io.StringIO() as stderr_buf:
                                    with contextlib.redirect_stderr(stderr_buf):
                                        out_decompressed = entry.get_decompressed_body()
                                        out_decrypted = entry.get_decrypted()
                                    # Check that there were no warnings
                                    self.assertEqual(stderr_buf.getvalue(), "")


if __name__ == '__main__':
    print(f"\nTesting module {psptool.__version__}")
    unittest.main()
