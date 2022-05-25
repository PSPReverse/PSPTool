import subprocess
import unittest
import psptool


class TestCli(unittest.TestCase):
    def setUp(self) -> None:
        binary_version = subprocess.run(['psptool', '--version'], stdout=subprocess.PIPE).stdout.decode('utf-8')
        print(f"Testing binary {binary_version}")

    def test_help_message(self):
        result = subprocess.run(['psptool', '-h'], stdout=subprocess.PIPE)
        self.assertTrue(
            b"Display, extract, and manipulate AMD PSP firmware inside BIOS ROMs" in result.stdout
        )


if __name__ == '__main__':
    unittest.main()
