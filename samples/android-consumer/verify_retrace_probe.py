#!/usr/bin/env python3
"""Verify that the final APK retains the crash probe's effective source position."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


ORIGINAL_CLASS = "com.example.dexcfgsample.ReleaseCrashProbe"
ORIGINAL_METHOD = "divideForRetrace"
METHOD_DESCRIPTOR = "(I)I"
SOURCE_LINE = 18


def mapping_target(mapping: Path | None) -> tuple[str, str, int]:
    if mapping is None:
        return ORIGINAL_CLASS, ORIGINAL_METHOD, SOURCE_LINE

    final_class = None
    class_header = re.compile(
        rf"^{re.escape(ORIGINAL_CLASS)} -> ([^:]+):$")
    method_entry = re.compile(
        rf"^\s+(\d+):\d+:int {ORIGINAL_METHOD}\(int\):"
        rf"{SOURCE_LINE}:{SOURCE_LINE} -> (\S+)$")
    for line in mapping.read_text(encoding="utf-8").splitlines():
        header = class_header.match(line)
        if header:
            final_class = header.group(1)
            continue
        if final_class is None:
            continue
        if line and not line[0].isspace() and " -> " in line:
            break
        method = method_entry.match(line)
        if method:
            return final_class, method.group(2), int(method.group(1))
    raise AssertionError(
        f"cannot resolve {ORIGINAL_CLASS}.{ORIGINAL_METHOD}:{SOURCE_LINE} in {mapping}")


def verify(apkanalyzer: Path, apk: Path, mapping: Path | None) -> None:
    final_class, final_method, expected_line = mapping_target(mapping)
    code = subprocess.run(
        [str(apkanalyzer), "dex", "code", "--class", final_class, str(apk)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout

    method_start = re.compile(
        rf"^\.method\s+.*\s{re.escape(final_method)}"
        rf"{re.escape(METHOD_DESCRIPTOR)}$")
    in_method = False
    current_line = None
    division_line = None
    switch_count = 0
    for raw_line in code.splitlines():
        line = raw_line.strip()
        if not in_method:
            in_method = method_start.match(line) is not None
            continue
        if line == ".end method":
            break
        position = re.match(r"^\.line\s+(\d+)$", line)
        if position:
            current_line = int(position.group(1))
        if "sparse-switch" in line:
            switch_count += 1
        if line.startswith("div-int"):
            if division_line is not None:
                raise AssertionError("crash probe contains more than one div-int instruction")
            division_line = current_line

    if not in_method:
        raise AssertionError(f"final method {final_class}.{final_method}{METHOD_DESCRIPTOR} missing")
    if switch_count < 2:
        raise AssertionError(f"crash probe was not strongly flattened: {switch_count} switch(es)")
    if division_line != expected_line:
        raise AssertionError(
            f"div-int effective line {division_line!r} != expected residual line {expected_line}")

    print(
        f"verified {final_class}.{final_method}{METHOD_DESCRIPTOR}: "
        f"strong CFG with effective line {division_line}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apkanalyzer", required=True, type=Path)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--mapping", type=Path)
    args = parser.parse_args()
    verify(args.apkanalyzer, args.apk, args.mapping)


if __name__ == "__main__":
    main()
