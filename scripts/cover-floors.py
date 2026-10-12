#!/usr/bin/env python3
"""Enforce the project-wide 70 percent package coverage floor."""
import collections
import pathlib
import sys

totals = collections.defaultdict(lambda: [0, 0])
for line in pathlib.Path("coverage.out").read_text(encoding="utf-8").splitlines()[1:]:
    location, statements, count = line.rsplit(" ", 2)
    package = location.rsplit("/", 1)[0]
    totals[package][0] += int(statements)
    totals[package][1] += int(statements) if int(count) else 0

failures = []
for package, (total, covered) in sorted(totals.items()):
    percent = 100 * covered / total if total else 100
    print(f"{package}: {percent:.1f}% (floor 70%)")
    if total and 100 * covered < 70 * total:
        failures.append(package)

if not totals:
    sys.exit("Empty coverage profile")
if failures:
    sys.exit("Coverage below floor: " + ", ".join(failures))
