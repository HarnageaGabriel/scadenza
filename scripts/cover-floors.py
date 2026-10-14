#!/usr/bin/env python3
"""Enforce per-package coverage floors (70 percent, 85 for internal/renewal)."""
import collections
import pathlib
import sys

DEFAULT_FLOOR = 70
# Packages that must meet a higher floor than the project default. The renewal
# classification is the 0.1.0 core answer, so it carries the 85 percent floor
# required by M4b.
FLOORS = {"internal/renewal": 85}

totals = collections.defaultdict(lambda: [0, 0])
for line in pathlib.Path("coverage.out").read_text(encoding="utf-8").splitlines()[1:]:
    location, statements, count = line.rsplit(" ", 2)
    package = location.rsplit("/", 1)[0]
    totals[package][0] += int(statements)
    totals[package][1] += int(statements) if int(count) else 0

failures = []
for package, (total, covered) in sorted(totals.items()):
    floor = next((value for suffix, value in FLOORS.items() if package.endswith(suffix)), DEFAULT_FLOOR)
    percent = 100 * covered / total if total else 100
    print(f"{package}: {percent:.1f}% (floor {floor}%)")
    if total and 100 * covered < floor * total:
        failures.append(f"{package} ({percent:.1f}% < {floor}%)")

if not totals:
    sys.exit("Empty coverage profile")
if failures:
    sys.exit("Coverage below floor: " + ", ".join(failures))
