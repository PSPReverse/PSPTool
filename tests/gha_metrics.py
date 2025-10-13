import os
import subprocess
import sys

print("# Metrics")
print()

try:
    files = os.listdir("tests/integration/fixtures/roms")
except FileNotFoundError:
    print("Failed to generate output metrics (No files found in `tests/integration/fixtures/roms`)")
    exit(0)

if len(files) == 0:
    print("Failed to generate output metrics (No files found in `tests/integration/fixtures/roms`)")
    exit(0)
    
stdout_lines = 0
stderr_lines = 0

for file in files:
    process = subprocess.run(["psptool", f"tests/integration/fixtures/roms/{file}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout_lines += len(process.stdout.decode().splitlines())
    stderr_lines += len(process.stderr.decode().splitlines())

if len(files) != 0:
    error_ratio = round((stderr_lines / (stdout_lines + stderr_lines)) * 100, 2)
    print("## `psptool` command line interface metrics")
    print()
    print("| Metric | Value |")
    print("|--------|-------|")
    print(f"| Files Processed | {len(files)} |")
    print(f"| Stdout Lines | {stdout_lines:,} |")
    print(f"| Stderr Lines | {stderr_lines:,} |")
    print(f"| Total Lines | {stdout_lines + stderr_lines:,} |")
    print(f"| Error Ratio | {error_ratio}% |")
    print()

successful = 0
failed = 0
# supress output
stdout = sys.stdout
# stderr = sys.stderr
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

# imported here to supress output from psptool
from psptool import PSPTool

failed_files = []
for file in files:
    try:
        
        p = PSPTool.from_file(f"tests/integration/fixtures/roms/{file}")
        successful += 1
    except:
        failed += 1
        failed_files.append(file)

sys.stdout = stdout

success_rate = round((successful / len(files)) * 100, 2)
failure_rate = round((failed / len(files)) * 100, 2)

print("## `PSPTool` python library metrics")
print()
print("| Status | Count | Percentage |")
print("|--------|-------|------------|")
print(f"| ✓ Successful | {successful} | {success_rate}% |")
print(f"| ✗ Failed | {failed} | {failure_rate}% |")
print(f"| **Total** | **{len(files)}** | **100%** |")
print()

if failed_files:
    print("### Failed Files")
    print()
    for file in failed_files:
        print(f"- `{file}`")
else:
    print("*All files parsed successfully!*")