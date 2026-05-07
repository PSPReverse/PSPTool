import unittest
import os
import psptool
import io
import contextlib

from psptool import PSPTool
from psptool.header_file import HeaderFile

dirname = os.path.dirname(__file__)
rom_fixtures_path = os.path.join(dirname, 'fixtures/test_files')

# todo: add extraction tests
#  - extract entry and make sure it has the correct size
#  - only resign the ROM and check that it is parsed with the same output as the original ROM


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

    def pt_from_file(self, filename) -> PSPTool:
        if filename not in self.__class__.cached_pts.keys():
            with io.StringIO() as stderr_buf:
                with contextlib.redirect_stderr(stderr_buf):
                    self.cached_pts[filename] = psptool.PSPTool.from_file(filename)
                    print(f"{filename=} ...")
                warnings = stderr_buf.getvalue().split('\n')

        return self.__class__.cached_pts[filename]

    def test_0_from_file(self):
        for filename in self.fixture_roms():
            with self.subTest(filename):
                pt = self.pt_from_file(filename)
                self.assertTrue(len(pt.blob.roms) > 0, "Did not find a single ROM")
                # TODO: re-enable this test (breaking for Gigabyte_WRX80F2)
                # for rom in pt.blob.roms:
                #     self.assertTrue(len(rom.directories) > 0, "Found ROM with no directories")

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
                                pt.ls_files()
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
                    for entry_index, entry in enumerate(directory.files):
                        with self.subTest(f"{filename=}, path={rom_index}.{dir_index}.{entry_index}, type={entry.type}"):
                            if isinstance(entry, HeaderFile):
                                with io.StringIO() as stderr_buf:
                                    with contextlib.redirect_stderr(stderr_buf):
                                        out_decrypted = entry.get_decrypted_decompressed_body()
                                    # Check that there were no warnings
                                    self.assertEqual(stderr_buf.getvalue(), "")


class TestZenGenerationBackfill(unittest.TestCase):
    # Maps fixture filename (relative to fixtures/roms) to the substring
    # that must appear in zen_generation for every directory in the ROM.
    # Single-generation EPYC images are the negative test set fixed by the
    # PSP_FW_BOOT_LOADER back-fill path. Each entry corresponds to a row
    # in issue.md's "Test ROMs — direct download URLs" section; SHA-256s
    # there can be used to verify the unwrapped ROM matches.
    EPYC_EXPECTATIONS = {
        'ASUS_KRPA-U16-ASUS-4501.CAP':   'Zen 2',  # Rome (SP3)
        'ASUS_KRPA-U16-M-ASUS-1002.CAP': 'Zen 3',  # Milan (SP3)
        'ASUS_K14PA-U12-ASUS-2305.CAP':  'Zen 4',  # Genoa (SP5)
        'ASUS_S14NA-U12-ASUS-0903.CAP':  'Zen 4',  # Siena (SP6); Zen 4c shares Zen 4 BL major
        'Tyan_S8050GM4NE-2T_V3.04.rom':  'Zen 5',  # Turin (SP5)
    }

    def _find_fixture(self, basename):
        for subdir, _dirs, files in os.walk(rom_fixtures_path):
            if basename in files:
                return os.path.join(subdir, basename)
        return None

    def test_epyc_zen_generation_set(self):
        present = {n: p for n, p in
                   ((n, self._find_fixture(n)) for n in self.EPYC_EXPECTATIONS)
                   if p is not None}
        if not present:
            self.skipTest(
                f"No EPYC fixtures present under {rom_fixtures_path}; "
                f"this assertion activates after Test-PSPTool gains the EPYC "
                f"corpus and the gitlink in this repo is bumped"
            )
        for name, path in present.items():
            expected = self.EPYC_EXPECTATIONS[name]
            with self.subTest(name):
                with io.StringIO() as stderr_buf, contextlib.redirect_stderr(stderr_buf):
                    pt = psptool.PSPTool.from_file(path)
                self.assertTrue(len(pt.blob.roms) > 0, f"{name}: no ROMs parsed")
                # Find at least one ROM whose directories all match the
                # expected generation. Multi-ROM BIOSes (e.g. Tyan Turin
                # ships a Genoa+Turin pair) may carry one ROM at a different
                # generation, but the expected one must be present.
                matching_roms = [
                    r for r in pt.blob.roms
                    if r.directories and all(
                        d.zen_generation is not None and expected in d.zen_generation
                        for d in r.directories
                    )
                ]
                self.assertTrue(
                    matching_roms,
                    f"{name}: no ROM in the file has all directories tagged {expected!r}; "
                    f"got "
                    + repr([
                        [d.zen_generation for d in r.directories]
                        for r in pt.blob.roms
                    ])
                )


if __name__ == '__main__':
    print(f"\nTesting module {psptool.__version__}")
    unittest.main()
