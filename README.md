# File Integrity Checker

A DFIR utility for creating, verifying, and comparing SHA-256 hash baselines to detect unauthorized file modifications.

## Supported Modes and Options

### Modes
* `baseline <directory> -o <output_file>`: Generate a SHA-256 hash baseline for all files in the target directory.
* `verify <baseline_file> [-o <report_file>]`: Verify current files against a saved baseline.
* `diff <baseline_file_1> <baseline_file_2> [-o <report_file>]`: Compare two baseline files and report differences.

### Options
* `-o <file>`: Write report output to the specified file.
* `-h`: Show the help message.

## Exit Codes

* **0 (PASS)**: All checks passed successfully.
* **1 (FAIL)**: Fatal error or integrity failure detected (e.g., file mismatch, invalid arguments).
* **2 (WARN)**: Non-fatal warnings (e.g., missing files, newly added files).

## How to Test Locally

1. **Make the script executable:**
   ```bash
   chmod +x integrity_checker.sh
   ```

2. **Create a test directory and generate a baseline:**
   ```bash
   mkdir test_dir
   echo "hello" > test_dir/file1.txt
   ./integrity_checker.sh baseline test_dir -o baseline1.txt
   ```

3. **Verify the baseline (should PASS):**
   ```bash
   ./integrity_checker.sh verify baseline1.txt
   ```

4. **Modify the directory and verify again (should WARN or FAIL):**
   ```bash
   touch test_dir/new_file.txt
   ./integrity_checker.sh verify baseline1.txt
   ```

5. **Generate a second baseline and compare them:**
   ```bash
   ./integrity_checker.sh baseline test_dir -o baseline2.txt
   ./integrity_checker.sh diff baseline1.txt baseline2.txt
   ```
