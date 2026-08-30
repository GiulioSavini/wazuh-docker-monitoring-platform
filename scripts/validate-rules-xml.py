#!/usr/bin/env python3
"""Check that every Wazuh rule and decoder file is well-formed XML.

Wazuh rule and decoder files are *fragments*: a decoder file legitimately
contains several top-level <decoder> elements with no single wrapping root.
Running `xmllint --noout` on one therefore fails with "Extra content at the end
of the document" even though the file is perfectly valid input for Wazuh, which
concatenates them under a root of its own.

So each file is wrapped the same way before parsing. That keeps the check
honest: it catches an unclosed tag or a stray character, which is what actually
breaks a ruleset, without rejecting the normal shape of these files.
"""

import pathlib
import sys
import xml.etree.ElementTree as ET

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"


def main() -> int:
    files = sorted(RULES_DIR.rglob("*.xml"))
    if not files:
        print(f"No XML files found under {RULES_DIR}", file=sys.stderr)
        return 1

    failures = 0
    for path in files:
        try:
            ET.fromstring(f"<wazuh_fragment>{path.read_text(encoding='utf-8')}</wazuh_fragment>")
        except ET.ParseError as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"\n{failures} of {len(files)} files are malformed.", file=sys.stderr)
        return 1

    print(f"{len(files)} rule and decoder files are well-formed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
