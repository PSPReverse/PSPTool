import contextlib
import io
import os
import unittest

import psptool
import psptrace

trace_fixtures_path = 'tests/integration/fixtures/traces/'
rom_fixtures_path = 'tests/integration/fixtures/roms/'


class TestPSPTrace(unittest.TestCase):
    def fixture_traces_and_roms(self):
        for subdir, dirs, files in os.walk(trace_fixtures_path):
            for file in files:
                if file[0] == '.':
                    continue
                if 'pickle' in file:
                    continue
                assert file[-3:] in ['txt', 'csv']
                tracefile = os.path.join(subdir, file)
                romfile = os.path.join(rom_fixtures_path, file[:-3] + 'rom')
                assert os.path.exists(romfile), \
                    "Expecting for each .txt/.csv file in traces a .rom file with the same name"
                print(f"{tracefile=}, {romfile=}")
                yield tracefile, romfile

    def test_basic(self):
        for tracefile, romfile in self.fixture_traces_and_roms():
            # Remove cache file first
            try:
                os.remove(tracefile + '.pickle')
            except FileNotFoundError:
                pass
            with self.subTest(f"{tracefile=} {romfile=}"):
                with io.StringIO() as stdout_buf:
                    with contextlib.redirect_stdout(stdout_buf):
                        with io.StringIO() as stderr_buf:
                            with contextlib.redirect_stderr(stderr_buf):
                                pt = psptrace.PSPTrace(tracefile, romfile, limit_rows=100)
                                pt.display_all()
                    stdout = stdout_buf.getvalue()
                    self.assertTrue(
                        'Parsed and stored a database of' in stdout,
                        stdout
                    )
                    self.assertTrue(
                        '+------+' in stdout,
                        stdout
                    )


if __name__ == '__main__':
    print(f"Testing PSPTool module {psptool.__version__}")
    print(f"Testing PSPTrace module {psptrace.__version__}")
    unittest.main()
