#!/bin/bash

# integrity_checker.sh
# Author: Jacob Contreras
# A DFIR utility for creating, verifying, and comparing SHA-256 hash baselines
# to detect unauthorized file modifications.

# Exit codes
readonly EXIT_PASS=0
readonly EXIT_FAIL=1
readonly EXIT_WARN=2

# Global counters
TOTAL_FILES=0
MATCHED=0
MISMATCHED=0
MISSING=0
NEW_FILES=0
ERRORS=0
OVERALL_STATUS=$EXIT_PASS

# Prints usage information and exits.
# Only main and usage may terminate the script.
usage() {
    cat <<EOF
Usage: $(basename "$0") <mode> [options]

Modes:
  baseline <directory> -o <output_file>
      Generate a SHA-256 hash baseline for all files in <directory>.

  verify <baseline_file> [-o <report_file>]
      Verify current files against a saved baseline.

  diff <baseline_file_1> <baseline_file_2> [-o <report_file>]
      Compare two baseline files and report differences.

Options:
  -o <file>    Write report output to <file>
  -h           Show this help message

Exit Codes:
  0  PASS    All checks passed
  1  FAIL    Fatal error or integrity failure detected
  2  WARN    Non-fatal warnings (e.g., missing files, minor mismatches)
EOF
    exit "$EXIT_FAIL"
}

# Checks if a path is a valid, readable directory.
# Parameters: $1 - path to check
# Returns: 0 if valid, 1 if not
# Does NOT print output.
validate_directory() {
    local dir="$1"
    [[ -d "$dir" && -r "$dir" ]]
    return $?
}

# Checks if a path is a valid, readable file.
# Parameters: $1 - path to check
# Returns: 0 if valid, 1 if not
# Does NOT print output.
validate_file() {
    local filepath="$1"
    [[ -f "$filepath" && -r "$filepath" ]]
    return $?
}

# Checks if a baseline file has the expected hash/path format.
# Parameters: $1 - baseline file path
# Returns: 0 if valid, 2 if minor issues (warnings), 1 if invalid
# Does NOT print output.
validate_baseline_format() {
    local bfile="$1"
    local line_count
    local bad_lines

    line_count=$(wc -l < "$bfile" 2>/dev/null)

    # Empty file is a failure
    if [[ "$line_count" -eq 0 ]]; then
        return 1
    fi

    # Check for lines that don't match expected format: 64-char-hex  filepath
    # The optional TARGET_DIR header comment is allowed and excluded from the check
    bad_lines=$(grep -cvE '^(# TARGET_DIR=.+|[a-f0-9]{64}  .+)' "$bfile" 2>/dev/null)

    if [[ "$bad_lines" -gt 0 ]]; then
        # Some bad lines but some good lines = warning
        local good_lines=$(grep -cE '^[a-f0-9]{64}  .+' "$bfile" 2>/dev/null)
        if [[ "$good_lines" -gt 0 ]]; then
            return 2
        fi
        return 1
    fi

    return 0
}

# Computes the SHA-256 hash of a single file.
# Parameters: $1 - file path
# Outputs: "hash  filepath" to stdout (consumed via command substitution)
compute_hash() {
    local filepath="$1"
    sha256sum "$filepath" 2>/dev/null
}

# Walks a target directory, hashes all files, writes baseline file.
# Parameters: $1 - target directory, $2 - output file
generate_baseline() {
    local target_dir="$1"
    local output_file="$2"
    local hash_line
    local file_count=0
    local error_count=0

    echo "File Integrity Checker: Baseline Generation"
    echo "Target Directory: $target_dir"
    echo "Output File:      $output_file"
    echo "Date:             $(date)"
    echo " "

    # Write the header and clear any previous content
    echo "# TARGET_DIR=$target_dir" > "$output_file"

    # Find all regular files and hash them
    while IFS= read -r filepath; do
        hash_line=$(compute_hash "$filepath")
        if [[ $? -eq 0 ]]; then
            echo "$hash_line" >> "$output_file"
            file_count=$((file_count + 1))
        else
            echo "  [ERROR] Could not hash: $filepath" >&2
            error_count=$((error_count + 1))
        fi
    done < <(find "$target_dir" -type f 2>/dev/null | sort)

    TOTAL_FILES=$file_count
    ERRORS=$error_count

    echo ""
    echo "Files hashed: $file_count"

    if [[ $error_count -gt 0 ]]; then
        echo "Errors:       $error_count"
    fi

    # Show top 5 largest files in baseline
    echo ""
    echo "--- Top 5 Largest Files ---"
    find "$target_dir" -type f -printf '%s %p\n' 2>/dev/null | sort -nr | head -n 5
}

# Reads a baseline file, re-hashes each file, reports mismatches.
# Parameters: $1 - baseline file path, $2 - optional report file
verify_baseline() {
    local baseline_file="$1"
    local report_file="$2"
    local stored_hash
    local stored_path
    local current_hash
    local details=""

    echo "File Integrity Checker: Verification"
    echo "Baseline File: $baseline_file"
    echo "Date:          $(date)"
    echo " "

    local total=0
    local match=0
    local mismatch=0
    local miss=0

    while IFS= read -r line; do
        # Skip comment lines (# TARGET_DIR=...)
        [[ "$line" == \#* ]] && continue

        stored_hash=$(echo "$line" | cut -c 1-64)
        stored_path=$(echo "$line" | cut -c 67-)

        total=$((total + 1))

        if ! validate_file "$stored_path"; then
            echo "[REMOVED]   $stored_path"
            details+="[REMOVED]   $stored_path"
            details+=$'\n'
            miss=$((miss + 1))
            continue
        fi

        current_hash=$(compute_hash "$stored_path" | cut -c 1-64)

        if [[ "$stored_hash" == "$current_hash" ]]; then
            echo "[UNCHANGED] $stored_path"
            details+="[UNCHANGED] $stored_path"
            details+=$'\n'
            match=$((match + 1))
        else
            echo "[CHANGED]   $stored_path"
            details+="[CHANGED]   $stored_path"
            details+=$'\n'
            mismatch=$((mismatch + 1))
        fi
    done < "$baseline_file"

    MATCHED=$match
    MISMATCHED=$mismatch
    MISSING=$miss

    # Check for new files in the directory not in the baseline file
    local baseline_dir
    baseline_dir=$(grep '^# TARGET_DIR=' "$baseline_file" | cut -d'=' -f2)
    # Read the target directory stored in the baseline header
    if validate_directory "$baseline_dir"; then
        local new_count=0
        while IFS= read -r filepath; do
            if ! grep -q "$filepath" "$baseline_file" 2>/dev/null; then
                echo "[ADDED]     $filepath"
                details+="[ADDED]     $filepath"
                details+=$'\n'
                new_count=$((new_count + 1))
                total=$((total + 1))
            fi
        done < <(find "$baseline_dir" -type f 2>/dev/null | sort)
        NEW_FILES=$new_count
    fi

    TOTAL_FILES=$total

    # Write report if requested
    if [[ -n "$report_file" ]]; then
        {
            echo "Verification Report - $(date)"
            echo "Baseline: $baseline_file"
            echo ""
            echo "$details"
            echo ""
            echo "Total: $total | Unchanged: $match | Changed: $mismatch | Removed: $miss | Added: $new_count"
        } > "$report_file"
    fi
}

# Compares two baseline files and reports added, removed, and changed files.
# Parameters: $1 - baseline file 1, $2 - baseline file 2, $3 - optional report file
diff_baselines() {
    local file1="$1"
    local file2="$2"
    local report_file="$3"

    echo "File Integrity Checker: Baseline Diff"
    echo "Baseline 1: $file1"
    echo "Baseline 2: $file2"
    echo "Date:       $(date)"
     echo " "

    local tmp_paths1="/tmp/ic_paths1_$$"
    local tmp_paths2="/tmp/ic_paths2_$$"
    local added=0
    local removed=0
    local changed=0
    local unchanged=0

    # Extract sorted file paths from each baseline (skip comment lines)
    grep -v '^#' "$file1" | cut -c 67- | sort > "$tmp_paths1"
    grep -v '^#' "$file2" | cut -c 67- | sort > "$tmp_paths2"

    local details=""

    while IFS= read -r line; do
        if [[ "$line" == "< "* ]]; then
            path="${line:2}"
            echo "[REMOVED] $path"
            details+="[REMOVED] $path"
            details+=$'\n'
            removed=$((removed + 1))
        elif [[ "$line" == "> "* ]]; then
            path="${line:2}"
            echo "[ADDED]   $path"
            details+="[ADDED]   $path"
            details+=$'\n'
            added=$((added + 1))
        fi
    done < <(diff "$tmp_paths1" "$tmp_paths2")

    # Files in both, compare hashes
    while IFS= read -r path; do
        local hash1
        local hash2
        hash1=$(grep "$path" "$file1" | cut -c 1-64 | head -n 1)
        hash2=$(grep "$path" "$file2" | cut -c 1-64 | head -n 1)

        if [[ "$hash1" != "$hash2" ]]; then
            echo "[CHANGED] $path"
            details+="[CHANGED] $path"
            details+=$'\n'
            changed=$((changed + 1))
        else
            echo "[UNCHANGED] $path"
            details+="[UNCHANGED] $path"
            details+=$'\n'
            unchanged=$((unchanged + 1))
        fi
    done < <(comm -12 "$tmp_paths1" "$tmp_paths2")

    TOTAL_FILES=$((added + removed + changed + unchanged))
    NEW_FILES=$added
    MISSING=$removed
    MISMATCHED=$changed
    MATCHED=$unchanged

    # Write report if requested
    if [[ -n "$report_file" ]]; then
        {
            echo "Diff Report - $(date)"
            echo "Baseline 1: $file1"
            echo "Baseline 2: $file2"
            echo ""
            echo "$details"
            echo ""
            echo "Total: $TOTAL_FILES | Added: $added | Removed: $removed | Changed: $changed | Unchanged: $unchanged"
        } > "$report_file"
    fi

    # Cleanup temp files
    rm -f "$tmp_paths1" "$tmp_paths2"
}

# Prints the final summary with derived metrics and the STATUS line.
print_summary() {
    echo ""
    echo "SUMMARY"
    echo "  Total files:   $TOTAL_FILES"
    [[ $MATCHED -gt 0 ]]    && echo "  Unchanged:     $MATCHED"
    [[ $MISMATCHED -gt 0 ]]  && echo "  Changed:       $MISMATCHED"
    [[ $MISSING -gt 0 ]]     && echo "  Removed:       $MISSING"
    [[ $NEW_FILES -gt 0 ]]   && echo "  Added:         $NEW_FILES"
    [[ $ERRORS -gt 0 ]]      && echo "  Errors:        $ERRORS"
    echo " "

    # Determine overall status
    if [[ $MISMATCHED -gt 0 || $ERRORS -gt 0 ]]; then
        OVERALL_STATUS=$EXIT_FAIL
        echo "STATUS: FAIL"
    elif [[ $MISSING -gt 0 || $NEW_FILES -gt 0 ]]; then
        OVERALL_STATUS=$EXIT_WARN
        echo "STATUS: WARN"
    else
        OVERALL_STATUS=$EXIT_PASS
        echo "STATUS: PASS"
    fi
}

# Only main and usage may terminate the script.
main() {
    local mode="$1"
    local report_file=""

    if [[ -z "$mode" || "$mode" == "-h" ]]; then
        usage
    fi

    shift

    case "$mode" in
        baseline)
            local target_dir="$1"
            shift 2>/dev/null

            # Parse -o flag
            while getopts ":o:" opt; do
                case "$opt" in
                    o) report_file="$OPTARG" ;;
                    *) usage ;;
                esac
            done

            if [[ -z "$target_dir" ]]; then
                echo "Error: directory argument required." >&2
                usage
            fi

            if ! validate_directory "$target_dir"; then
                echo "Error: '$target_dir' is not a valid directory." >&2
                exit $EXIT_FAIL
            fi

            if [[ -z "$report_file" ]]; then
                echo "Error: -o <output_file> is required for baseline mode." >&2
                usage
            fi

            generate_baseline "$target_dir" "$report_file"
            print_summary
            ;;

        verify)
            local baseline_file="$1"
            shift 2>/dev/null
            OPTIND=1

            while getopts ":o:" opt; do
                case "$opt" in
                    o) report_file="$OPTARG" ;;
                    *) usage ;;
                esac
            done

            if [[ -z "$baseline_file" ]]; then
                echo "Error: baseline file argument required." >&2
                usage
            fi

            if ! validate_file "$baseline_file"; then
                echo "Error: '$baseline_file' is not a valid file." >&2
                exit $EXIT_FAIL
            fi

            validate_baseline_format "$baseline_file"
            local fmt_status=$?
            if [[ $fmt_status -eq 1 ]]; then
                echo "Error: '$baseline_file' is not a valid baseline file." >&2
                exit $EXIT_FAIL
            elif [[ $fmt_status -eq 2 ]]; then
                echo "Warning: '$baseline_file' contains some malformed lines." >&2
            fi

            verify_baseline "$baseline_file" "$report_file"
            print_summary
            ;;

        diff)
            local file1="$1"
            local file2="$2"
            shift 2 2>/dev/null
            OPTIND=1

            while getopts ":o:" opt; do
                case "$opt" in
                    o) report_file="$OPTARG" ;;
                    *) usage ;;
                esac
            done

            if [[ -z "$file1" || -z "$file2" ]]; then
                echo "Error: two baseline file arguments required." >&2
                usage
            fi

            if ! validate_file "$file1"; then
                echo "Error: '$file1' is not a valid file." >&2
                exit $EXIT_FAIL
            fi

            if ! validate_file "$file2"; then
                echo "Error: '$file2' is not a valid file." >&2
                exit $EXIT_FAIL
            fi

            validate_baseline_format "$file1"
            local fmt1=$?
            if [[ $fmt1 -eq 1 ]]; then
                echo "Error: '$file1' is not a valid baseline file." >&2
                exit $EXIT_FAIL
            fi

            validate_baseline_format "$file2"
            local fmt2=$?
            if [[ $fmt2 -eq 1 ]]; then
                echo "Error: '$file2' is not a valid baseline file." >&2
                exit $EXIT_FAIL
            fi

            diff_baselines "$file1" "$file2" "$report_file"
            print_summary
            ;;

        *)
            echo "Error: unknown mode '$mode'." >&2
            usage
            ;;
    esac

    exit $OVERALL_STATUS
}

main "$@"
