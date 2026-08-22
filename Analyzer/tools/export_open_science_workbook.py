#!/usr/bin/env python3
"""Export analyzer results as an evidence-oriented Open Science workbook."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter


SCHEMA_VERSION = "open-science-evidence-v1"
EXCEL_CELL_LIMIT = 32767
TEXT_LIMIT = 32000

COLORS = {
    "navy": "17365D",
    "blue": "2F75B5",
    "light_blue": "D9EAF7",
    "green": "C6E0B4",
    "orange": "F8CBAD",
    "yellow": "FFF2CC",
    "gray": "D9E1F2",
    "light_gray": "E7E6E6",
    "white": "FFFFFF",
    "red": "F4CCCC",
}

STATE_FILLS = {
    "E": PatternFill("solid", fgColor=COLORS["green"]),
    "N": PatternFill("solid", fgColor=COLORS["orange"]),
    "U": PatternFill("solid", fgColor=COLORS["yellow"]),
    "NA": PatternFill("solid", fgColor=COLORS["light_gray"]),
    "Enforceable": PatternFill("solid", fgColor=COLORS["green"]),
    "Non-Enforceable": PatternFill("solid", fgColor=COLORS["yellow"]),
    "N/A": PatternFill("solid", fgColor=COLORS["light_gray"]),
    "active": PatternFill("solid", fgColor=COLORS["yellow"]),
    "covered_by_final_proof": PatternFill("solid", fgColor=COLORS["light_blue"]),
}

THIN_GRAY = Side(style="thin", color="B7B7B7")
HEADER_FILL = PatternFill("solid", fgColor=COLORS["navy"])
SUBHEADER_FILL = PatternFill("solid", fgColor=COLORS["blue"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export systematic_analysis JSON as a detailed XLSX workbook."
    )
    parser.add_argument(
        "--input-dir",
        required=True,
        type=Path,
        help="Analyzer output directory containing summary.json and reports/.",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Destination .xlsx file.",
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def portable_text(value: Any, replacements: list[tuple[str, str]]) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = str(value)
    for source, target in replacements:
        if source:
            text = text.replace(source.rstrip("/") + "/", target.rstrip("/") + "/")
            text = text.replace(source, target)
    return text


def excel_text(value: Any, replacements: list[tuple[str, str]]) -> Any:
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return value
    text = portable_text(value, replacements)
    if len(text) <= TEXT_LIMIT:
        return text
    return text[: TEXT_LIMIT - 96] + "\n[TRUNCATED: see normalized evidence rows in this workbook]"


def joined(
    values: Iterable[Any] | None,
    replacements: list[tuple[str, str]],
    separator: str = "; ",
) -> str:
    if not values:
        return ""
    return separator.join(portable_text(value, replacements) for value in values)


def unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def reported_class(state: str) -> str:
    if state == "E":
        return "Enforceable"
    if state in {"N", "U"}:
        return "Non-Enforceable"
    return "N/A"


def state_subclass(state: str) -> str:
    return {
        "E": "Enforceable",
        "N": "Bypass-Certified",
        "U": "Unresolved",
        "NA": "Not Available",
    }.get(state, "Unresolved")


def coverage_for(report: dict[str, Any], domain: str) -> dict[str, Any]:
    return report.get(f"{domain}_path_coverage") or {}


def domain_state(report: dict[str, Any], domain: str) -> str:
    return report.get(f"{domain}_enforcement_state") or "U"


def domain_points(report: dict[str, Any], domain: str) -> list[str]:
    coverage = coverage_for(report, domain)
    key = "hooks" if domain == "lsm" else "checks"
    return coverage.get(key) or []


def gap_rows_for(
    report: dict[str, Any], domain: str, status: str
) -> list[dict[str, Any]]:
    coverage = coverage_for(report, domain)
    key = "unresolved_edges" if status == "active" else "covered_unresolved_edges"
    return coverage.get(key) or []


def gap_summary(report: dict[str, Any], domain: str) -> tuple[int, str, str]:
    gaps = gap_rows_for(report, domain, "active")
    categories = sorted({gap.get("category", "other") for gap in gaps})
    scopes = sorted({gap.get("resolution_scope", "unknown") for gap in gaps})
    return len(gaps), "; ".join(categories), "; ".join(scopes)


def objective_basis(
    report: dict[str, Any], domain: str, replacements: list[tuple[str, str]]
) -> str:
    state = domain_state(report, domain)
    coverage = coverage_for(report, domain)
    mechanism = "LSM-BPF" if domain == "lsm" else "conventional SIGKILL"
    if state == "NA":
        reason = report.get("availability_reason") or "No executable implementation in the evaluated build."
        return f"NA: {portable_text(reason, replacements)}"
    if state == "E":
        points = domain_points(report, domain)
        methods = coverage.get("proof_methods") or []
        if domain == "lsm":
            canonical = report.get("certified_bpf_lsm_hooks") or []
            point_text = joined(canonical, replacements) or joined(points, replacements)
            return (
                "E: every modeled normal-success alternative is covered by at least one "
                "veto-capable hook whose denial is certified to block the operation and remain "
                "a syscall error. Canonical BPF LSM hook(s): "
                f"{point_text or 'see LSM Hook Effects'}. Proof method(s): "
                f"{joined(methods, replacements) or 'recorded in path coverage'}."
            )
        return (
            "E: every modeled normal-success alternative reaches an effective current-task "
            "SIGKILL checkpoint whose abort effect is certified to eliminate normal syscall "
            f"completion. Checkpoint(s): {joined(points, replacements) or 'see Signal Check Effects'}. "
            f"Proof method(s): {joined(methods, replacements) or 'recorded in path coverage'}."
        )
    if state == "N":
        bypass_method = coverage.get("bypass_proof_method") or "recorded success witness"
        return (
            f"N (Bypass-Certified): at least one modeled feasible normal-success path is proven "
            f"to bypass every effective {mechanism} enforcement point. Success witness method: "
            f"{portable_text(bypass_method, replacements)}. Full witness: Evidence Paths."
        )
    gap_count, categories, scopes = gap_summary(report, domain)
    points = domain_points(report, domain)
    point_note = ""
    if points:
        point_note = (
            " Candidate point(s) were found but universal successful-path coverage or final "
            f"propagation was not established: {joined(points, replacements)}."
        )
    return (
        "U (Unresolved): neither universal enforcement nor a feasible successful bypass was "
        f"certified. Active unresolved edge(s): {gap_count}; category(s): {categories or 'not recorded'}; "
        f"scope(s): {scopes or 'not recorded'}.{point_note} See Proof Gaps."
    )


def style_sheet(
    sheet,
    headers: list[str],
    widths: dict[str, float] | None = None,
    freeze: str = "A2",
) -> None:
    widths = widths or {}
    sheet.freeze_panes = freeze
    sheet.auto_filter.ref = sheet.dimensions
    sheet.sheet_view.showGridLines = False
    for cell in sheet[1]:
        cell.fill = HEADER_FILL
        cell.font = Font(color=COLORS["white"], bold=True)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = Border(bottom=THIN_GRAY)
    sheet.row_dimensions[1].height = 32
    long_headers = {
        "objective_basis",
        "availability_reason",
        "reasons",
        "detail",
        "function_or_cfg_step",
        "proof_functions",
        "negative_reasons",
        "description",
        "value",
    }
    for index, header in enumerate(headers, start=1):
        default = 52 if header in long_headers else 18
        sheet.column_dimensions[get_column_letter(index)].width = widths.get(header, default)
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            if str(cell.value) in STATE_FILLS:
                cell.fill = STATE_FILLS[str(cell.value)]


def add_table_sheet(
    workbook: Workbook,
    title: str,
    headers: list[str],
    rows: Iterable[Iterable[Any]],
    replacements: list[tuple[str, str]],
    widths: dict[str, float] | None = None,
) -> Any:
    sheet = workbook.create_sheet(title)
    sheet.append(headers)
    for row in rows:
        sheet.append([excel_text(value, replacements) for value in row])
    style_sheet(sheet, headers, widths)
    return sheet


def add_readme_sheet(
    workbook: Workbook,
    counts: dict[str, Any],
    metadata: dict[str, Any],
    summary_hash: str,
) -> None:
    sheet = workbook.create_sheet("README")
    sheet.sheet_view.showGridLines = False
    sheet.merge_cells("A1:F1")
    sheet["A1"] = "Per-Syscall Enforceability Evidence — Linux 5.15 x86-64"
    sheet["A1"].fill = HEADER_FILL
    sheet["A1"].font = Font(color=COLORS["white"], bold=True, size=16)
    sheet["A1"].alignment = Alignment(horizontal="center")
    sheet.row_dimensions[1].height = 28

    sections = [
        (
            "Purpose",
            "Open Science evidence supporting the build-specific syscall classification produced by systematic_analysis. "
            "The workbook preserves the public two-class presentation (Enforceable versus Non-Enforceable) while exposing "
            "the analyzer's internal N/U distinction and the structured proof evidence for every syscall.",
        ),
        (
            "Reported classes",
            "Enforceable = internal state E. Non-Enforceable = internal state N or U. N/A = syscall implementation is unavailable "
            "in the evaluated build. N and U are never treated as equivalent evidence: N is a certified bypass, whereas U is unresolved.",
        ),
        (
            "Internal states",
            "E (Enforceable): every modeled normal-success alternative is covered by a certified enforcement point. "
            "N (Bypass-Certified): at least one feasible normal-success path is proven to bypass all effective enforcement points. "
            "U (Unresolved): neither universal enforcement nor a successful bypass is certified. "
            "NA: no executable implementation in the evaluated build.",
        ),
        (
            "Composition rule",
            "Any certified N alternative makes the syscall N; otherwise all alternatives must be E to produce E; any remaining unresolved "
            "alternative produces U. Equivalently: E+E=E, E+N=N, N+U=N, and E+U=U.",
        ),
        (
            "LSM-BPF evidence",
            "An E classification requires path coverage by BPF-attachable error-return LSM hooks and certified denial propagation: "
            "the hook denial blocks the operation, prevents normal syscall success, and remains encoded as an error. Exact errno identity is not required.",
        ),
        (
            "SIGKILL evidence",
            "An E classification requires an effective checkpoint at the analyzed callsite, a subject proven to be the current task, "
            "SIGKILL relevance, and a certified abort path that removes normal syscall completion.",
        ),
        (
            "Scope caveat",
            "The classification certifies successful-completion enforcement under the analyzer's modeled semantics. It does not independently "
            "prove that no incidental side effect occurs before every enforcement point. Unresolved control flow is exposed rather than guessed.",
        ),
        (
            "Evidence navigation",
            "Syscalls gives the paper-facing class and objective basis. LSM Evidence and SIGKILL Evidence expose domain-specific proof summaries. "
            "LSM Hook Effects and Signal Check Effects record enforcement semantics. Evidence Paths stores paths one step per row. "
            "Proof Gaps records active and proof-covered unresolved edges. Success Point Sets exposes the recorded per-alternative point sets.",
        ),
        (
            "Reproducibility",
            f"Analyzer frontend={metadata.get('frontend', '')}; semantics={metadata.get('enforcement_semantics', '')}; "
            f"summary.json SHA-256={summary_hash}. Host-specific source/build prefixes are normalized as <kernel> and <build>.",
        ),
        (
            "Counts",
            "LSM-BPF: E={E}, N={N}, U={U}, NA={NA}. Conventional SIGKILL: E={SE}, N={SN}, U={SU}, NA={SNA}.".format(
                E=counts["lsm_enforcement_states"]["E"],
                N=counts["lsm_enforcement_states"]["N"],
                U=counts["lsm_enforcement_states"]["U"],
                NA=counts["lsm_enforcement_states"]["NA"],
                SE=counts["sigkill_enforcement_states"]["E"],
                SN=counts["sigkill_enforcement_states"]["N"],
                SU=counts["sigkill_enforcement_states"]["U"],
                SNA=counts["sigkill_enforcement_states"]["NA"],
            ),
        ),
    ]
    row = 3
    for heading, body in sections:
        sheet.merge_cells(start_row=row, start_column=1, end_row=row, end_column=2)
        sheet.cell(row, 1, heading)
        sheet.cell(row, 1).fill = SUBHEADER_FILL
        sheet.cell(row, 1).font = Font(color=COLORS["white"], bold=True)
        sheet.merge_cells(start_row=row, start_column=3, end_row=row, end_column=6)
        sheet.cell(row, 3, body)
        sheet.cell(row, 3).alignment = Alignment(vertical="top", wrap_text=True)
        sheet.row_dimensions[row].height = 58 if len(body) > 240 else 42
        row += 1
    for column, width in {"A": 18, "B": 4, "C": 32, "D": 32, "E": 32, "F": 32}.items():
        sheet.column_dimensions[column].width = width


def kernel_version(kernel_root: Path) -> str:
    makefile = kernel_root / "Makefile"
    if not makefile.exists():
        return "5.15 (reported evaluation target)"
    values: dict[str, str] = {}
    pattern = re.compile(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(.*)$")
    for line in makefile.read_text(encoding="utf-8", errors="replace").splitlines():
        match = pattern.match(line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    base = ".".join(values.get(key, "0") for key in ("VERSION", "PATCHLEVEL", "SUBLEVEL"))
    return base + values.get("EXTRAVERSION", "")


def config_values(config_path: Path) -> dict[str, str]:
    selected = {
        "CONFIG_SECURITY",
        "CONFIG_SECURITY_PATH",
        "CONFIG_BPF_SYSCALL",
        "CONFIG_BPF_JIT",
        "CONFIG_BPF_EVENTS",
        "CONFIG_BPF_LSM",
        "CONFIG_LSM",
        "CONFIG_MODULES",
    }
    result: dict[str, str] = {}
    if not config_path.exists():
        return result
    for raw in config_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.startswith("# CONFIG_") and raw.endswith(" is not set"):
            key = raw[2 : raw.index(" is not set")]
            if key in selected:
                result[key] = "not set"
            continue
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        if key in selected:
            result[key] = value
    return result


def main() -> None:
    args = parse_args()
    input_dir = args.input_dir.resolve()
    output = args.output.resolve()
    summary_path = input_dir / "summary.json"
    metadata_path = input_dir / "analysis_metadata.json"
    counts_path = input_dir / "reports" / "classification_counts.json"
    validation_path = input_dir / "reports" / "input_validation.json"
    for required in (summary_path, metadata_path, counts_path, validation_path):
        if not required.exists():
            raise SystemExit(f"required analyzer artifact is missing: {required}")

    reports: list[dict[str, Any]] = load_json(summary_path)
    metadata: dict[str, Any] = load_json(metadata_path)
    counts: dict[str, Any] = load_json(counts_path)
    validation: dict[str, Any] = load_json(validation_path)
    if len(reports) != counts.get("total_syscall_table_entries"):
        raise SystemExit("summary row count does not match classification_counts.json")
    for domain, count_key in (
        ("lsm", "lsm_enforcement_states"),
        ("sigkill", "sigkill_enforcement_states"),
    ):
        actual = Counter(domain_state(report, domain) for report in reports)
        expected = counts.get(count_key) or {}
        if any(actual[state] != expected.get(state, 0) for state in ("E", "N", "U", "NA")):
            raise SystemExit(
                f"{domain} state counts in summary.json do not match classification_counts.json"
            )

    kernel_root = Path(validation.get("kernel_root", ""))
    build_root = Path(validation.get("build_root", ""))
    replacements = [
        (str(kernel_root), "<kernel>"),
        (str(build_root), "<build>"),
        (str(input_dir), "<analysis-output>"),
    ]

    workbook = Workbook()
    workbook.remove(workbook.active)
    workbook.properties.title = "Per-Syscall Enforceability Evidence"
    workbook.properties.subject = "LSM-BPF and conventional SIGKILL syscall classification"
    workbook.properties.creator = "systematic_analysis open-science exporter"
    workbook.properties.description = (
        "Build-specific E/N/U/NA classifications with structured proof evidence."
    )
    summary_hash = sha256_file(summary_path)
    add_readme_sheet(workbook, counts, metadata, summary_hash)

    count_rows = []
    for mechanism, key in (("LSM-BPF", "lsm_enforcement_states"), ("Conventional SIGKILL", "sigkill_enforcement_states")):
        states = counts[key]
        applicable = states["E"] + states["N"] + states["U"]
        count_rows.append(
            [
                mechanism,
                states["E"],
                states["N"],
                states["U"],
                states["N"] + states["U"],
                states["NA"],
                applicable,
                applicable + states["NA"],
                states["E"] / applicable if applicable else 0,
            ]
        )
    counts_sheet = add_table_sheet(
        workbook,
        "Counts",
        [
            "mechanism",
            "E_enforceable",
            "N_bypass_certified",
            "U_unresolved",
            "reported_non_enforceable_N_plus_U",
            "NA",
            "implemented_syscalls",
            "table_entries",
            "established_coverage",
        ],
        count_rows,
        replacements,
        {"mechanism": 24, "reported_non_enforceable_N_plus_U": 30},
    )
    for cell in counts_sheet["I"][1:]:
        cell.number_format = "0.0%"

    syscall_rows = []
    for report in reports:
        lsm_state = domain_state(report, "lsm")
        signal_state = domain_state(report, "sigkill")
        syscall_rows.append(
            [
                report["number"],
                report.get("abi", ""),
                report["name"],
                report.get("entry", ""),
                report.get("start", ""),
                report.get("linked_symbol", ""),
                report.get("availability", ""),
                report.get("availability_reason", ""),
                reported_class(lsm_state),
                lsm_state,
                state_subclass(lsm_state),
                objective_basis(report, "lsm", replacements),
                joined(report.get("certified_bpf_lsm_hooks"), replacements),
                reported_class(signal_state),
                signal_state,
                state_subclass(signal_state),
                objective_basis(report, "sigkill", replacements),
                joined(domain_points(report, "sigkill"), replacements),
                f"checkpoints/syscalls/{report['number']}-{report['name']}.json",
                report.get("call_tree_file", ""),
            ]
        )
    add_table_sheet(
        workbook,
        "Syscalls",
        [
            "number",
            "abi",
            "syscall",
            "entry_symbol",
            "analysis_start",
            "linked_symbol",
            "availability",
            "availability_reason",
            "lsm_reported_class",
            "lsm_state",
            "lsm_subclass",
            "lsm_objective_basis",
            "certified_bpf_lsm_hooks",
            "sigkill_reported_class",
            "sigkill_state",
            "sigkill_subclass",
            "sigkill_objective_basis",
            "effective_sigkill_checks",
            "source_report_json",
            "call_tree_file",
        ],
        syscall_rows,
        replacements,
        {
            "number": 9,
            "abi": 10,
            "syscall": 22,
            "entry_symbol": 24,
            "analysis_start": 30,
            "linked_symbol": 28,
            "availability": 24,
            "availability_reason": 48,
            "lsm_reported_class": 20,
            "lsm_state": 10,
            "lsm_subclass": 20,
            "lsm_objective_basis": 78,
            "certified_bpf_lsm_hooks": 38,
            "sigkill_reported_class": 20,
            "sigkill_state": 12,
            "sigkill_subclass": 20,
            "sigkill_objective_basis": 78,
            "effective_sigkill_checks": 34,
            "source_report_json": 42,
            "call_tree_file": 34,
        },
    )

    lsm_rows = []
    signal_rows = []
    for report in reports:
        for domain, target in (("lsm", lsm_rows), ("sigkill", signal_rows)):
            state = domain_state(report, domain)
            coverage = coverage_for(report, domain)
            active_count, active_categories, active_scopes = gap_summary(report, domain)
            covered_count = len(gap_rows_for(report, domain, "covered"))
            eligibility = (report.get("proof_eligibility") or {}).get(domain) or {}
            point_sets_key = "success_path_hook_sets" if domain == "lsm" else "success_path_check_sets"
            common = [
                report["number"],
                report.get("abi", ""),
                report["name"],
                reported_class(state),
                state,
                state_subclass(state),
                coverage.get("status", ""),
                objective_basis(report, domain, replacements),
                len(coverage.get(point_sets_key) or []),
                joined(coverage.get("proof_methods"), replacements),
                joined(coverage.get("proof_functions"), replacements),
                coverage.get("bypass_proof_method", ""),
                bool(coverage.get("bypass_proof_path")),
                bool(coverage.get("unproven_bypass_path")),
                active_count,
                active_categories,
                active_scopes,
                covered_count,
                joined(coverage.get("reasons"), replacements, "\n"),
                eligibility.get("status", ""),
                eligibility.get("positive_proof", False),
                eligibility.get("negative_proof", False),
                joined(eligibility.get("reasons"), replacements, "\n"),
            ]
            if domain == "lsm":
                target.append(
                    common
                    + [
                        joined(report.get("certified_bpf_lsm_hooks"), replacements),
                        joined(report.get("certified_enforcing_lsm_hooks"), replacements),
                        joined(report.get("effective_enforcing_lsm_hooks"), replacements),
                        joined(coverage.get("hooks"), replacements),
                        joined(report.get("inactive_config_lsm_hooks"), replacements),
                        len(report.get("unproven_lsm_candidates") or []),
                    ]
                )
            else:
                target.append(
                    common
                    + [
                        joined(coverage.get("checks"), replacements),
                        joined(report.get("current_task_reachable_signal_checks"), replacements),
                        joined(report.get("current_task_always_signal_checks"), replacements),
                        joined(report.get("unknown_subject_signal_checks"), replacements),
                        joined((report.get("reachable_signal_check_categories") or {}).get("group_exit"), replacements),
                        joined((report.get("reachable_signal_check_categories") or {}).get("fatal_pending"), replacements),
                        joined((report.get("reachable_signal_check_categories") or {}).get("generic_pending"), replacements),
                    ]
                )

    common_headers = [
        "number",
        "abi",
        "syscall",
        "reported_class",
        "state",
        "subclass",
        "coverage_status",
        "objective_basis",
        "recorded_success_alternatives",
        "proof_methods",
        "proof_functions",
        "bypass_proof_method",
        "has_certified_bypass_path",
        "has_unproven_bypass_path",
        "active_gap_count",
        "active_gap_categories",
        "active_gap_resolution_scopes",
        "covered_gap_count",
        "coverage_reasons",
        "proof_eligibility_status",
        "positive_proof",
        "negative_proof",
        "eligibility_reasons",
    ]
    domain_widths = {
        "number": 9,
        "abi": 10,
        "syscall": 22,
        "reported_class": 20,
        "state": 10,
        "subclass": 20,
        "coverage_status": 18,
        "objective_basis": 78,
        "recorded_success_alternatives": 24,
        "proof_methods": 46,
        "proof_functions": 70,
        "bypass_proof_method": 48,
        "active_gap_categories": 42,
        "active_gap_resolution_scopes": 34,
        "coverage_reasons": 80,
        "eligibility_reasons": 80,
    }
    add_table_sheet(
        workbook,
        "LSM Evidence",
        common_headers
        + [
            "certified_canonical_bpf_hooks",
            "certified_security_wrappers",
            "path_local_effective_wrappers",
            "coverage_candidate_wrappers",
            "inactive_config_hooks",
            "unproven_candidate_count",
        ],
        lsm_rows,
        replacements,
        domain_widths,
    )
    add_table_sheet(
        workbook,
        "SIGKILL Evidence",
        common_headers
        + [
            "coverage_checks",
            "current_task_reachable_checks",
            "current_task_always_checks",
            "unknown_subject_checks",
            "group_exit_checks",
            "fatal_pending_checks",
            "generic_pending_checks",
        ],
        signal_rows,
        replacements,
        domain_widths,
    )

    hook_effect_rows = []
    llvm_rows = []
    signal_effect_rows = []
    evidence_path_rows = []
    success_set_rows = []
    proof_gap_rows = []
    unproven_lsm_rows = []

    def add_path(
        report: dict[str, Any],
        domain: str,
        path_type: str,
        evidence_id: str,
        path: list[str] | None,
        direction: str,
    ) -> None:
        if not path:
            return
        path_id = f"{report['number']}:{report['name']}:{domain}:{path_type}:{evidence_id or '-'}"
        for index, step in enumerate(path, start=1):
            evidence_path_rows.append(
                [
                    report["number"],
                    report.get("abi", ""),
                    report["name"],
                    domain,
                    domain_state(report, domain),
                    path_type,
                    evidence_id,
                    path_id,
                    direction,
                    index,
                    step,
                ]
            )

    for report in reports:
        certified_wrappers = set(report.get("certified_enforcing_lsm_hooks") or [])
        effective_wrappers = set(report.get("effective_enforcing_lsm_hooks") or [])
        for effect_index, effect in enumerate(report.get("lsm_error_effects") or [], start=1):
            hook = effect.get("hook", "")
            path_id = (
                f"{report['number']}:{report['name']}:lsm:"
                f"lsm_error_effect:{hook}:{effect_index}"
            )
            hook_effect_rows.append(
                [
                    report["number"],
                    report.get("abi", ""),
                    report["name"],
                    domain_state(report, "lsm"),
                    hook,
                    effect.get("bpf_hook", ""),
                    hook in certified_wrappers,
                    hook in effective_wrappers,
                    effect.get("hook_kind", ""),
                    effect.get("blocks_operation", ""),
                    effect.get("terminates_syscall", ""),
                    effect.get("errno_propagation", ""),
                    effect.get("failure_encoding", ""),
                    joined(effect.get("overwrite_sites"), replacements),
                    effect.get("proof_method", ""),
                    effect.get("llvm_verification", ""),
                    joined(effect.get("callsite_functions"), replacements),
                    path_id,
                    len(effect.get("llvm_evidence") or []),
                ]
            )
            add_path(
                report,
                "lsm",
                "lsm_error_effect",
                f"{hook}:{effect_index}",
                effect.get("proof_path"),
                "enforcement point toward syscall entry",
            )
            for evidence_index, fact in enumerate(effect.get("llvm_evidence") or [], start=1):
                llvm_rows.append(
                    [
                        report["number"],
                        report.get("abi", ""),
                        report["name"],
                        domain_state(report, "lsm"),
                        hook,
                        evidence_index,
                        fact.get("verification", ""),
                        fact.get("function", ""),
                        fact.get("source_function", ""),
                        fact.get("source_file", ""),
                        fact.get("source_line", ""),
                        fact.get("source_column", ""),
                        fact.get("result_used", False),
                        fact.get("controls_branch", False),
                        fact.get("reaches_return", False),
                        fact.get("must_return_exact", False),
                        fact.get("must_return_negative_on_error", False),
                        fact.get("must_return_negative_on_false", False),
                        fact.get("must_return_negative_on_true", False),
                        joined(fact.get("use_kinds"), replacements),
                        fact.get("module", ""),
                    ]
                )

        for path_index, path in enumerate(report.get("signal_check_paths") or [], start=1):
            check = path.get("check", "")
            path_id = (
                f"{report['number']}:{report['name']}:sigkill:"
                f"signal_check_effect:{check}:{path_index}"
            )
            signal_effect_rows.append(
                [
                    report["number"],
                    report.get("abi", ""),
                    report["name"],
                    domain_state(report, "sigkill"),
                    check,
                    path.get("callsite_id", ""),
                    path.get("category", ""),
                    path.get("sigkill_relevance", ""),
                    path.get("subject", ""),
                    path.get("traversal", ""),
                    path.get("function", ""),
                    path.get("blocks_operation", ""),
                    path.get("terminates_syscall", ""),
                    path.get("errno_propagation", ""),
                    path.get("failure_encoding", ""),
                    path.get("abort_effect", ""),
                    path_id,
                    len(path.get("indirect_edges") or []),
                ]
            )
            add_path(
                report,
                "sigkill",
                "signal_check_effect",
                f"{check}:{path_index}",
                path.get("proof_path"),
                "checkpoint toward syscall entry",
            )

        for domain in ("lsm", "sigkill"):
            coverage = coverage_for(report, domain)
            point_paths_key = "hook_proof_paths" if domain == "lsm" else "check_proof_paths"
            for point, path in sorted((coverage.get(point_paths_key) or {}).items()):
                add_path(
                    report,
                    domain,
                    "coverage_point",
                    point,
                    path,
                    "enforcement point toward syscall entry",
                )
            add_path(
                report,
                domain,
                "certified_bypass",
                coverage.get("bypass_proof_method", ""),
                coverage.get("bypass_proof_path"),
                "syscall entry toward successful return witness",
            )
            add_path(
                report,
                domain,
                "unproven_bypass",
                "unproven",
                coverage.get("unproven_bypass_path"),
                "syscall entry toward potential return",
            )

            set_key = "success_path_hook_sets" if domain == "lsm" else "success_path_check_sets"
            for index, point_set in enumerate(coverage.get(set_key) or [], start=1):
                points = point_set or []
                state = domain_state(report, domain)
                if points:
                    interpretation = "modeled alternative contains the listed enforcing point(s)"
                elif state == "N" and coverage.get("bypass_proof_path"):
                    interpretation = "empty point set; syscall has a separately certified successful bypass witness"
                elif state == "U":
                    interpretation = "empty point set; unresolved or uncovered alternative, not itself a certified bypass"
                else:
                    interpretation = "empty point set recorded"
                success_set_rows.append(
                    [
                        report["number"],
                        report.get("abi", ""),
                        report["name"],
                        domain,
                        state,
                        coverage.get("status", ""),
                        index,
                        len(points),
                        joined(points, replacements),
                        interpretation,
                    ]
                )

            seen_gaps: set[tuple[str, ...]] = set()
            for gap_status in ("active", "covered"):
                status_label = "active" if gap_status == "active" else "covered_by_final_proof"
                for gap in gap_rows_for(report, domain, gap_status):
                    key = tuple(
                        str(gap.get(field, ""))
                        for field in ("caller", "kind", "category", "resolution_scope", "symbol", "expression", "detail")
                    )
                    dedupe = (status_label,) + key
                    if dedupe in seen_gaps:
                        continue
                    seen_gaps.add(dedupe)
                    proof_gap_rows.append(
                        [
                            report["number"],
                            report.get("abi", ""),
                            report["name"],
                            domain,
                            domain_state(report, domain),
                            status_label,
                            gap.get("caller", ""),
                            gap.get("kind", ""),
                            gap.get("category", ""),
                            gap.get("resolution_scope", ""),
                            gap.get("symbol", ""),
                            gap.get("expression", ""),
                            gap.get("detail", ""),
                        ]
                    )

        for candidate in report.get("unproven_lsm_candidates") or []:
            unproven_lsm_rows.append(
                [
                    report["number"],
                    report.get("abi", ""),
                    report["name"],
                    domain_state(report, "lsm"),
                    candidate.get("hook", ""),
                    candidate.get("function", ""),
                    candidate.get("hook_kind", ""),
                    candidate.get("reason", ""),
                ]
            )

    evidence_path_ids = {row[7] for row in evidence_path_rows}
    missing_path_refs = [
        row[17]
        for row in hook_effect_rows
        if row[17] and row[17] not in evidence_path_ids
    ] + [
        row[16]
        for row in signal_effect_rows
        if row[16] and row[16] not in evidence_path_ids
    ]
    if missing_path_refs:
        raise SystemExit(
            "effect evidence references missing Evidence Paths IDs: "
            + ", ".join(missing_path_refs[:5])
        )

    add_table_sheet(
        workbook,
        "LSM Hook Effects",
        [
            "number",
            "abi",
            "syscall",
            "lsm_state",
            "security_wrapper",
            "canonical_bpf_hook",
            "in_final_certified_cover",
            "path_local_effective",
            "hook_kind",
            "blocks_operation",
            "terminates_syscall",
            "errno_propagation",
            "failure_encoding",
            "overwrite_sites",
            "proof_method",
            "llvm_verification",
            "callsite_functions",
            "evidence_path_id",
            "llvm_evidence_count",
        ],
        hook_effect_rows,
        replacements,
        {
            "syscall": 22,
            "security_wrapper": 36,
            "canonical_bpf_hook": 34,
            "callsite_functions": 60,
            "evidence_path_id": 54,
        },
    )
    add_table_sheet(
        workbook,
        "Signal Check Effects",
        [
            "number",
            "abi",
            "syscall",
            "sigkill_state",
            "check",
            "callsite_id",
            "category",
            "sigkill_relevance",
            "subject",
            "traversal",
            "function",
            "blocks_operation",
            "terminates_syscall",
            "errno_propagation",
            "failure_encoding",
            "abort_effect",
            "evidence_path_id",
            "indirect_edge_count",
        ],
        signal_effect_rows,
        replacements,
        {"syscall": 22, "function": 58, "evidence_path_id": 54},
    )
    add_table_sheet(
        workbook,
        "LLVM Evidence",
        [
            "number",
            "abi",
            "syscall",
            "lsm_state",
            "security_wrapper",
            "evidence_index",
            "verification",
            "function",
            "source_function",
            "source_file",
            "source_line",
            "source_column",
            "result_used",
            "controls_branch",
            "reaches_return",
            "must_return_exact",
            "must_return_negative_on_error",
            "must_return_negative_on_false",
            "must_return_negative_on_true",
            "use_kinds",
            "module",
        ],
        llvm_rows,
        replacements,
        {"syscall": 22, "source_file": 60, "use_kinds": 52, "module": 60},
    )
    add_table_sheet(
        workbook,
        "Evidence Paths",
        [
            "number",
            "abi",
            "syscall",
            "domain",
            "state",
            "path_type",
            "evidence_id",
            "path_id",
            "path_direction",
            "step_index",
            "function_or_cfg_step",
        ],
        evidence_path_rows,
        replacements,
        {
            "syscall": 22,
            "path_type": 24,
            "evidence_id": 46,
            "path_id": 64,
            "path_direction": 42,
            "function_or_cfg_step": 90,
        },
    )
    add_table_sheet(
        workbook,
        "Proof Gaps",
        [
            "number",
            "abi",
            "syscall",
            "domain",
            "state",
            "gap_status",
            "caller",
            "kind",
            "category",
            "resolution_scope",
            "symbol",
            "expression",
            "detail",
        ],
        proof_gap_rows,
        replacements,
        {
            "syscall": 22,
            "gap_status": 26,
            "caller": 62,
            "kind": 42,
            "category": 42,
            "resolution_scope": 32,
            "symbol": 42,
            "expression": 52,
            "detail": 90,
        },
    )
    add_table_sheet(
        workbook,
        "Success Point Sets",
        [
            "number",
            "abi",
            "syscall",
            "domain",
            "state",
            "coverage_status",
            "alternative_index",
            "point_count",
            "enforcement_points",
            "interpretation",
        ],
        success_set_rows,
        replacements,
        {"syscall": 22, "enforcement_points": 60, "interpretation": 78},
    )
    add_table_sheet(
        workbook,
        "Unproven LSM",
        [
            "number",
            "abi",
            "syscall",
            "lsm_state",
            "security_wrapper",
            "function",
            "hook_kind",
            "reason",
        ],
        unproven_lsm_rows,
        replacements,
        {"syscall": 22, "function": 70, "reason": 80},
    )

    unavailable_rows = [
        [
            report["number"],
            report.get("abi", ""),
            report["name"],
            report.get("entry", ""),
            report.get("linked_symbol", ""),
            report.get("linked_symbol_type", ""),
            report.get("availability", ""),
            report.get("availability_reason", ""),
        ]
        for report in reports
        if domain_state(report, "lsm") == "NA"
    ]
    add_table_sheet(
        workbook,
        "Unavailable",
        [
            "number",
            "abi",
            "syscall",
            "table_entry",
            "linked_symbol",
            "linked_symbol_type",
            "availability",
            "objective_reason",
        ],
        unavailable_rows,
        replacements,
        {"syscall": 22, "table_entry": 30, "linked_symbol": 32, "objective_reason": 80},
    )

    provenance_rows: list[list[Any]] = [
        ["workbook", "schema_version", SCHEMA_VERSION],
        ["workbook", "generated_at_utc", datetime.now(timezone.utc).isoformat()],
        ["evaluation", "kernel_version", kernel_version(kernel_root)],
        ["evaluation", "architecture", "x86-64"],
        ["evaluation", "syscall_table_entries", counts.get("total_syscall_table_entries")],
        ["evaluation", "implemented_syscalls", counts.get("applicable_syscalls")],
        ["evaluation", "unavailable_syscalls", counts.get("unavailable_syscalls")],
        ["analyzer", "frontend", metadata.get("frontend", "")],
        ["analyzer", "enforcement_semantics", metadata.get("enforcement_semantics", "")],
        ["analyzer", "classification_engine", metadata.get("classification_engine", "")],
        ["analyzer", "frontend_cache_fingerprint", metadata.get("frontend_cache_fingerprint", "")],
        ["analyzer", "frontend_cache_built_at", metadata.get("frontend_cache_built_at", "")],
        ["input", "validation_status", validation.get("status", "")],
        ["input", "strict_validation", validation.get("strict", "")],
        ["input", "compile_database_sha256", validation.get("compile_database_sha256", "")],
        ["input", "config_sha256", validation.get("config_sha256", "")],
        ["input", "summary_json_sha256", summary_hash],
        ["input", "analysis_metadata_sha256", sha256_file(metadata_path)],
        ["input", "classification_counts_sha256", sha256_file(counts_path)],
        ["input", "input_validation_sha256", sha256_file(validation_path)],
        ["input", "compile_command_count", validation.get("compile_command_count", "")],
        ["input", "unique_compile_sources", validation.get("unique_compile_sources", "")],
        ["input", "ambiguous_compile_variants", validation.get("ambiguous_compile_variants", "")],
        ["input", "unresolved_link_symbols", validation.get("unresolved_link_symbols", "")],
    ]
    config_path = Path(validation.get("config_path", ""))
    for key, value in sorted(config_values(config_path).items()):
        provenance_rows.append(["kernel_config", key, value])
    for index, warning in enumerate(validation.get("warnings") or [], start=1):
        provenance_rows.append(["validation_warning", f"warning_{index}", warning])
    for artifact, status in sorted((validation.get("artifacts") or {}).items()):
        provenance_rows.append(["build_artifact", f"{artifact}.present", status.get("present", False)])
        if status.get("sha256"):
            provenance_rows.append(["build_artifact", f"{artifact}.sha256", status["sha256"]])

    analyzer_root = Path(__file__).resolve().parent.parent
    for relative in (
        "main.go",
        "frontend_cache.go",
        "input_validation.go",
        "tools/clang_extractor.cpp",
        "tools/llvm_hook_verifier.cpp",
        "tools/export_open_science_workbook.py",
        "systematic_analysis",
    ):
        path = analyzer_root / relative
        if path.exists() and path.is_file():
            provenance_rows.append(["analyzer_artifact", f"{relative}.sha256", sha256_file(path)])
    add_table_sheet(
        workbook,
        "Provenance",
        ["category", "field", "value"],
        provenance_rows,
        replacements,
        {"category": 24, "field": 42, "value": 100},
    )

    dictionary_rows = [
        ["Syscalls", "reported_class", "Paper-facing class: E is Enforceable; N and U are Non-Enforceable; NA is N/A."],
        ["Syscalls", "state", "Internal evidence state E, N, U, or NA."],
        ["LSM/SIGKILL Evidence", "objective_basis", "Structured English summary generated only from recorded classification and proof fields."],
        ["LSM/SIGKILL Evidence", "coverage_status", "Analyzer path-coverage result: enforcing, non_enforcing, or uncertain."],
        ["LSM/SIGKILL Evidence", "active_gap_count", "Unresolved proof edges that still prevent certification."],
        ["LSM/SIGKILL Evidence", "covered_gap_count", "Local unresolved edges rendered irrelevant by a later universal proof or certified bypass."],
        ["LSM Hook Effects", "blocks_operation", "Whether a negative hook result is proven to stop the guarded operation."],
        ["LSM Hook Effects", "terminates_syscall", "Whether the denial is proven to prevent normal syscall completion."],
        ["LSM Hook Effects", "errno_propagation", "exact, normalized, overwritten, conditional, ignored, or unknown."],
        ["Signal Check Effects", "subject", "Task whose signal state is inspected; positive SIGKILL evidence requires current-task."],
        ["Signal Check Effects", "abort_effect", "Whether the checkpoint's true result is proven to eliminate normal syscall completion."],
        ["Evidence Paths", "path_direction", "Direction in which path steps are recorded; enforcement paths and bypass paths use different directions."],
        ["Proof Gaps", "gap_status", "active blocks certification; covered_by_final_proof is retained for transparency but does not block the final result."],
        ["Proof Gaps", "resolution_scope", "implementation_improvable or static_analysis_limit, as emitted by the analyzer."],
        ["Success Point Sets", "enforcement_points", "Hook/check set recorded for one modeled successful-path alternative; empty U sets are not certified bypasses."],
        ["Unavailable", "objective_reason", "Build-linked reason for NA, including empty table slots and weak ENOSYS stubs."],
    ]
    add_table_sheet(
        workbook,
        "Data Dictionary",
        ["sheet", "column", "description"],
        dictionary_rows,
        replacements,
        {"sheet": 28, "column": 36, "description": 110},
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(output)

    reopened = load_workbook(output, read_only=True, data_only=False)
    required_sheets = {
        "README",
        "Counts",
        "Syscalls",
        "LSM Evidence",
        "SIGKILL Evidence",
        "LSM Hook Effects",
        "Signal Check Effects",
        "LLVM Evidence",
        "Evidence Paths",
        "Proof Gaps",
        "Success Point Sets",
        "Unproven LSM",
        "Unavailable",
        "Provenance",
        "Data Dictionary",
    }
    missing = required_sheets.difference(reopened.sheetnames)
    if missing:
        raise SystemExit(f"generated workbook is missing sheets: {sorted(missing)}")
    if reopened["Syscalls"].max_row != len(reports) + 1:
        raise SystemExit("generated Syscalls sheet has an unexpected row count")
    reopened.close()
    print(output)


if __name__ == "__main__":
    main()
