# secretscanner_final.py: Checks files or any directories for API keys, tokens, or passwords.

import argparse
import logging
import os
import re

# list of patterns to look for (name and the regex for it)
patterns_to_check = [
    ("AWS Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack Bot", re.compile(r"\bxoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}\b")),
    ("Slack User", re.compile(r"\bxoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}\b")),
    ("Stripe Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b")),
    ("Heroku Key", re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("Mailgun Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")),
]

def mask_key(key_string, chars_to_show=4):
    # hides middle part so we dont print full secrets
    if len(key_string) <= chars_to_show * 2:
        return "***"
    start = key_string[:chars_to_show]
    end = key_string[-chars_to_show:]
    return f"{start}...{end}"

def is_text_file(path):
    # checks if file is plaintext
    try:
        f = open(path, "rb")
        chunk = f.read(2048)
        f.close()
        chunk.decode("utf-8")
        return True
    except:
        logging.debug(f"skipping binary or unreadable: {path}")
        return False

def walk_files(path):
    # gets all files from either a single file or directory
    if os.path.isfile(path):
        yield path
    else:
        for root, dirs, files in os.walk(path):
            for f in files:
                yield os.path.join(root, f)

def scan_single_file(filepath):
    # scans one file and returns matches found + returns tuples of file, line_number, pattern_name, what_matched
    if not is_text_file(filepath):
        return
    
    try:
        f = open(filepath, "r", encoding="utf-8", errors="ignore")
        line_number = 1
        for line in f:
            for pattern_name, regex in patterns_to_check:
                matches = regex.finditer(line)
                for m in matches:
                    yield (filepath, line_number, pattern_name, m.group(0))
            line_number += 1
        f.close()
    except Exception as e:
        logging.warning(f"error reading {filepath}: {e}")

def run_scanner(target_path):
    # main function that runs the scan
    logging.debug(f"Starting scan for: {target_path}")
    num_found = 0
    
    all_files = walk_files(target_path)
    for f in all_files:
        logging.debug(f"Scanning file: {f}")
        results = scan_single_file(f)
        for file, line, pattern, matched_text in results:
            num_found += 1
            hidden = mask_key(matched_text)
            print(f"{file}:{line} | {pattern} >> {hidden}")
        logging.debug(f"Finished file: {f} findings so far: {num_found}")
    logging.debug(f"Finished scan. Number of findings: {num_found}")
    return num_found

def main():
    parser = argparse.ArgumentParser(
        description="The program scans for hardcoded secrets in files or directories.",
        add_help=False,
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=30)
    )
    parser.add_argument("path", metavar="PATH", help="file/folder to scan")
    parser.add_argument("-v", dest="verbose", action="store_true", help="show debug logs")
    parser.add_argument("-h", action="help", help="shows this help message")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    target = os.path.abspath(args.path)
    if not os.path.exists(target):
        logging.error(f"Path not found: {target}")
        raise SystemExit(1)

    logging.info(f"Scanning: {target}")
    total = run_scanner(target)

    print("\nResults:")
    print(f"Found {total} secrets!")
    if total == 0:
        print("Nothing found (your code is probably clean!)")

if __name__ == "__main__":
    main()