"""
FedAIDA-IDS — PCAP/PCAPNG → Flow Features (≈80) Extraction

This module provides an *offline* extractor which converts packet captures into
CICFlowMeter-style flow CSVs. We intentionally support multiple backends because
Windows + Python version constraints vary across labs:

- Backend A (preferred when available): `cicflowmeter` CLI (Python tool)
- Backend B (fallback): Java CICFlowMeter jar (set CICFLOWMETER_JAR env var)

Outputs are CSV files suitable for `data/preprocess.py` loaders.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass(frozen=True)
class FlowExtractResult:
    backend: str
    outputs: list[str]


class FlowExtractorError(RuntimeError):
    pass


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(cmd: list[str], cwd: Optional[str] = None) -> None:
    p = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if p.returncode != 0:
        raise FlowExtractorError(
            "Flow extraction failed.\n"
            f"Command: {' '.join(cmd)}\n"
            f"ExitCode: {p.returncode}\n"
            f"Output:\n{p.stdout}"
        )


def extract_pcap_to_csv(
    pcap_path: str,
    out_csv_path: str,
    *,
    backend: str = "auto",
) -> FlowExtractResult:
    """
    Extract flow features from a single PCAP into a single CSV file.
    """
    pcap = Path(pcap_path)
    out_csv = Path(out_csv_path)
    out_csv.parent.mkdir(parents=True, exist_ok=True)

    chosen = backend
    if backend == "auto":
        if _which("cicflowmeter"):
            chosen = "cicflowmeter"
        elif os.environ.get("CICFLOWMETER_JAR"):
            chosen = "cicflowmeter_jar"
        else:
            chosen = "none"

    if chosen == "cicflowmeter":
        _run(["cicflowmeter", "-f", str(pcap), "-c", str(out_csv)])
        return FlowExtractResult(backend="cicflowmeter", outputs=[str(out_csv)])

    if chosen == "cicflowmeter_jar":
        jar = os.environ.get("CICFLOWMETER_JAR")
        if not jar:
            raise FlowExtractorError("CICFLOWMETER_JAR env var is not set.")
        # Many CICFlowMeter jars support: -f <pcap> -c <csv>
        _run(["java", "-jar", jar, "-f", str(pcap), "-c", str(out_csv)])
        return FlowExtractResult(backend="cicflowmeter_jar", outputs=[str(out_csv)])

    raise FlowExtractorError(
        "No PCAP→flow extractor backend available.\n"
        "Install a backend or configure one of:\n"
        "- Put `cicflowmeter` on PATH (recommended)\n"
        "- Set CICFLOWMETER_JAR to a CICFlowMeter jar path"
    )


def extract_directory(
    pcap_dir: str,
    out_dir: str,
    *,
    backend: str = "auto",
    patterns: Iterable[str] = ("*.pcap", "*.pcapng"),
) -> FlowExtractResult:
    """
    Extract all PCAP/PCAPNG files in a directory into flow CSV(s).

    If using `cicflowmeter` CLI, it supports directory mode: `-d <dir> -c <outdir>`.
    We use that when available because it is faster than per-file invocation.
    """
    src = Path(pcap_dir)
    dst = Path(out_dir)
    dst.mkdir(parents=True, exist_ok=True)

    pcap_files: list[Path] = []
    for pat in patterns:
        pcap_files.extend(sorted(src.glob(pat)))

    if not pcap_files:
        raise FlowExtractorError(f"No PCAP files found in: {pcap_dir}")

    chosen = backend
    if backend == "auto":
        if _which("cicflowmeter"):
            chosen = "cicflowmeter"
        elif os.environ.get("CICFLOWMETER_JAR"):
            chosen = "cicflowmeter_jar"
        else:
            chosen = "none"

    outputs: list[str] = []

    if chosen == "cicflowmeter":
        # Directory mode creates one CSV per input file (tool-dependent).
        _run(["cicflowmeter", "-d", str(src), "-c", str(dst)])
        outputs = [str(p) for p in sorted(dst.glob("*.csv"))]
        return FlowExtractResult(backend="cicflowmeter", outputs=outputs)

    # Fallback: per-file jar invocation
    if chosen == "cicflowmeter_jar":
        for p in pcap_files:
            out_csv = dst / (p.stem + ".csv")
            r = extract_pcap_to_csv(str(p), str(out_csv), backend="cicflowmeter_jar")
            outputs.extend(r.outputs)
        return FlowExtractResult(backend="cicflowmeter_jar", outputs=outputs)

    raise FlowExtractorError(
        "No PCAP→flow extractor backend available for directory extraction.\n"
        "Install `cicflowmeter` CLI or set CICFLOWMETER_JAR."
    )

