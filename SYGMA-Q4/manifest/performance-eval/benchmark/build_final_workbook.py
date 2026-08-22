#!/usr/bin/env python3
"""Build a publication-oriented Excel workbook from the final Q3 campaigns."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import statistics
from typing import Any, Iterable

from openpyxl import Workbook, load_workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.formatting.rule import ColorScaleRule, DataBarRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.table import Table, TableStyleInfo

from analyze import summarize


HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"

CAMPAIGN_SPECS = (
    ("Nginx", "q3-rerun3-nginx-*", 12, "latency"),
    ("Httpd", "q3-rerun3-httpd-*", 12, "latency"),
    ("Redis", "q3-rerun3-redis-*", 12, "throughput"),
    ("MySQL (50k tx)", "q3-rerun3-mysql-fixed50k-*", 12, "throughput"),
    ("Hotel 25 RPS", "q3-hotel-c2-rps25-*", 4, "latency"),
    ("Hotel 75 RPS", "q3-hotel-c2-rps75-*", 4, "latency"),
    ("Hotel 100 RPS", "q3-hotel-c2-rps100-*", 4, "latency"),
)

MODE_ORDER = ("default", "tetragon", "sygma", "sygma-all-trace")
MODE_LABEL = {
    "default": "Default",
    "tetragon": "Tetragon",
    "sygma": "SYGMA",
    "sygma-all-trace": "SYGMA-all-trace",
}
MODE_COLORS = {
    "default": "7F8C8D",
    "tetragon": "F39C12",
    "sygma": "1976D2",
    "sygma-all-trace": "D32F2F",
}

NAVY = "17365D"
BLUE = "D9EAF7"
LIGHT_BLUE = "EAF3F8"
YELLOW = "FFF2CC"
RED = "FCE4D6"
GREEN = "E2F0D9"
WHITE = "FFFFFF"
GRAY = "666666"
THIN_GRAY = Side(style="thin", color="D9E1F2")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def select_campaign(label: str, pattern: str, expected: int, basis: str) -> dict[str, Any]:
    candidates = sorted(RESULTS.glob(pattern), key=lambda path: path.stat().st_mtime, reverse=True)
    for path in candidates:
        summary_path = path / "summary.json"
        trials_path = path / "trials.jsonl"
        metadata_path = path / "metadata.json"
        if not (summary_path.is_file() and trials_path.is_file() and metadata_path.is_file()):
            continue
        summary = read_json(summary_path)
        if summary.get("valid_trial_count") != expected or summary.get("trial_count") != expected:
            continue
        trials = read_jsonl(trials_path)
        if len(trials) != expected or not all(trial.get("valid") for trial in trials):
            continue
        return {
            "label": label,
            "basis": basis,
            "path": path,
            "summary": summary,
            "metadata": read_json(metadata_path),
            "trials": trials,
        }
    raise RuntimeError(f"no complete campaign found for {label}: {pattern}")


def metric(group: dict[str, Any], name: str, stat: str = "mean") -> float | None:
    value = (group.get("metrics") or {}).get(name)
    if not isinstance(value, dict):
        return None
    result = value.get(stat)
    return float(result) if isinstance(result, (int, float)) else None


def groups_by_mode(campaign: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {group["mode"]: group for group in campaign["summary"]["groups"]}


def operation_count(trial: dict[str, Any]) -> int | None:
    performance = trial.get("performance") or {}
    for key in ("transactions", "requests"):
        value = performance.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return int(value)
    return None


def trial_derived(trial: dict[str, Any]) -> dict[str, float | int | None]:
    performance = trial.get("performance") or {}
    workload = ((trial.get("resources") or {}).get("scopes") or {}).get("workload") or {}
    cpu = workload.get("cpu_millicores_mean")
    wall = performance.get("wall_seconds")
    operations = operation_count(trial)
    cpu_seconds = None
    cpu_ms_per_op = None
    if isinstance(cpu, (int, float)) and isinstance(wall, (int, float)):
        cpu_seconds = float(cpu) * float(wall) / 1000.0
        if operations:
            cpu_ms_per_op = cpu_seconds * 1000.0 / operations
    return {
        "operations": operations,
        "cpu_seconds_est": cpu_seconds,
        "cpu_ms_per_op_est": cpu_ms_per_op,
    }


def derived_stats(campaign: dict[str, Any], mode: str, name: str) -> dict[str, float | int] | None:
    values: list[float] = []
    for trial in campaign["trials"]:
        if trial.get("mode") != mode or not trial.get("valid"):
            continue
        value = trial_derived(trial).get(name)
        if isinstance(value, (int, float)):
            values.append(float(value))
    return summarize(values) if values else None


def degradation(campaign: dict[str, Any], mode: str) -> float | None:
    groups = groups_by_mode(campaign)
    default = groups["default"]
    current = groups[mode]
    if campaign["basis"] == "latency":
        base = metric(default, "latency_avg_ms")
        value = metric(current, "latency_avg_ms")
        if base and value is not None:
            return (value / base - 1.0) * 100.0
    else:
        base = metric(default, "throughput_ops_per_sec")
        value = metric(current, "throughput_ops_per_sec")
        if base and value is not None:
            return (base - value) / base * 100.0
    return None


def relative_change(value: float | None, base: float | None) -> float | None:
    if value is None or not base:
        return None
    return (value / base - 1.0) * 100.0


def route_share(group: dict[str, Any], route: str) -> float | None:
    total = metric(group, "route_total_count")
    value = metric(group, f"route_{route}_count")
    if total and value is not None:
        return value / total * 100.0
    return None


def title(ws: Any, text: str, subtitle: str, end_column: int) -> None:
    ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=end_column)
    ws["A1"] = text
    ws["A1"].font = Font(size=18, bold=True, color=WHITE)
    ws["A1"].fill = PatternFill("solid", fgColor=NAVY)
    ws["A1"].alignment = Alignment(vertical="center")
    ws.row_dimensions[1].height = 28
    ws.merge_cells(start_row=2, start_column=1, end_row=2, end_column=end_column)
    ws["A2"] = subtitle
    ws["A2"].font = Font(size=10, italic=True, color=GRAY)
    ws["A2"].alignment = Alignment(wrap_text=True, vertical="top")
    ws.row_dimensions[2].height = 34


def write_headers(ws: Any, row: int, headers: Iterable[str]) -> None:
    for column, value in enumerate(headers, 1):
        cell = ws.cell(row=row, column=column, value=value)
        cell.font = Font(bold=True, color=WHITE)
        cell.fill = PatternFill("solid", fgColor=NAVY)
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        cell.border = Border(bottom=THIN_GRAY)
    ws.row_dimensions[row].height = 32


def add_table(ws: Any, start_row: int, end_row: int, end_column: int, name: str) -> None:
    if end_row <= start_row:
        return
    table = Table(displayName=name, ref=f"A{start_row}:{ws.cell(start_row, end_column).column_letter}{end_row}")
    table.tableStyleInfo = TableStyleInfo(
        name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False,
        showRowStripes=True, showColumnStripes=False,
    )
    ws.add_table(table)


def finish_sheet(ws: Any, freeze: str, widths: dict[str, float], landscape: bool = True) -> None:
    ws.freeze_panes = freeze
    for column, width in widths.items():
        ws.column_dimensions[column].width = width
    ws.sheet_view.showGridLines = False
    ws.auto_filter.ref = ws.dimensions
    ws.page_setup.orientation = "landscape" if landscape else "portrait"
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.print_options.horizontalCentered = True


def write_overview(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.active
    ws.title = "Overview"
    ws.sheet_properties.tabColor = NAVY
    title(
        ws,
        "SYGMA Q3 Final Benchmark Results",
        "최종 채택 캠페인만 포함. Core/MySQL은 모드별 n=3, Hotel은 모드별 n=1.",
        8,
    )

    ws["A4"] = "Generated (UTC)"
    ws["B4"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    ws["D4"] = "Valid trials"
    ws["E4"] = sum(campaign["summary"]["valid_trial_count"] for campaign in campaigns)
    ws["G4"] = "Invalid trials"
    ws["H4"] = sum(campaign["summary"]["invalid_trial_count"] for campaign in campaigns)
    for cell in ("A4", "D4", "G4"):
        ws[cell].font = Font(bold=True, color=NAVY)

    headers = ("Workload", "Campaign", "Basis", "Repetitions/mode", "Valid", "Invalid", "Result path")
    write_headers(ws, 6, headers)
    row = 7
    for campaign in campaigns:
        summary = campaign["summary"]
        repetitions = min(group["valid_trials"] for group in summary["groups"])
        values = (
            campaign["label"], campaign["path"].name,
            "Avg latency increase" if campaign["basis"] == "latency" else "Throughput reduction",
            repetitions, summary["valid_trial_count"], summary["invalid_trial_count"],
            str(campaign["path"]),
        )
        for column, value in enumerate(values, 1):
            ws.cell(row=row, column=column, value=value)
        ws.cell(row=row, column=7).hyperlink = campaign["path"].as_uri()
        ws.cell(row=row, column=7).style = "Hyperlink"
        row += 1
    add_table(ws, 6, row - 1, len(headers), "OverviewCampaigns")

    start = row + 2
    degradation_header = start
    write_headers(ws, degradation_header, ("Workload", "Degradation basis", "Tetragon (%)", "SYGMA (%)", "All-trace (%)"))
    for campaign in campaigns:
        start += 1
        ws.cell(start, 1, campaign["label"])
        ws.cell(start, 2, "Latency" if campaign["basis"] == "latency" else "Throughput")
        for column, mode in enumerate(("tetragon", "sygma", "sygma-all-trace"), 3):
            ws.cell(start, column, degradation(campaign, mode))
            ws.cell(start, column).number_format = '0.0"%";[Red]-0.0"%"'
    degradation_last = start
    add_table(ws, degradation_header, degradation_last, 5, "OverviewDegradation")
    ws.conditional_formatting.add(
        f"C{degradation_header + 1}:E{degradation_last}",
        ColorScaleRule(start_type="min", start_color=GREEN, mid_type="percentile", mid_value=50,
                       mid_color=YELLOW, end_type="max", end_color="F8696B"),
    )

    notes_row = degradation_last + 3
    notes = (
        "해석 주의사항",
        "• Positive degradation means worse performance; negative means improvement.",
        "• Application CPU는 workload container cgroup만 포함합니다.",
        "• Framework CPU에는 host-side sygma-tracer(/system.slice/containerd.service)가 포함되지 않습니다.",
        "• CPU-seconds 및 CPU ms/op는 Metrics API 평균 mCPU × wall time으로 계산한 근사치입니다.",
        "• Hotel은 n=1이므로 표준편차와 95% CI를 논문 통계로 해석할 수 없습니다.",
        "• SYGMA route counter는 정책 결정 route hit이며 실제 SIGKILL/deny 횟수가 아닙니다.",
    )
    ws.merge_cells(start_row=notes_row, start_column=1, end_row=notes_row, end_column=8)
    ws.cell(notes_row, 1, notes[0]).font = Font(bold=True, color=NAVY)
    for offset, note in enumerate(notes[1:], 1):
        current = notes_row + offset
        ws.merge_cells(start_row=current, start_column=1, end_row=current, end_column=8)
        ws.cell(current, 1, note)
        ws.cell(current, 1).alignment = Alignment(wrap_text=True)
        ws.cell(current, 1).fill = PatternFill("solid", fgColor=YELLOW)

    finish_sheet(ws, "A7", {"A": 19, "B": 42, "C": 24, "D": 17, "E": 10, "F": 10, "G": 68, "H": 14})


def write_performance(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Performance")
    ws.sheet_properties.tabColor = "4472C4"
    headers = (
        "Workload", "Mode", "N", "Basis", "Throughput mean", "Throughput SD",
        "Throughput CI95 low", "Throughput CI95 high", "Degradation vs default (%)",
        "Avg latency mean (ms)", "Avg latency SD", "Avg latency CI95 low",
        "Avg latency CI95 high", "p50 (ms)", "p95 (ms)", "p99 (ms)",
        "Max latency (ms)", "Error rate (%)",
    )
    title(ws, "Performance Summary", "Mean, sample SD, and Student-t 95% CI from valid trials.", len(headers))
    write_headers(ws, 4, headers)
    row = 5
    for campaign in campaigns:
        groups = groups_by_mode(campaign)
        for mode in MODE_ORDER:
            group = groups[mode]
            values = (
                campaign["label"], MODE_LABEL[mode], group["valid_trials"],
                "Latency increase" if campaign["basis"] == "latency" else "Throughput reduction",
                metric(group, "throughput_ops_per_sec"), metric(group, "throughput_ops_per_sec", "stdev"),
                metric(group, "throughput_ops_per_sec", "ci95_low"),
                metric(group, "throughput_ops_per_sec", "ci95_high"), degradation(campaign, mode),
                metric(group, "latency_avg_ms"), metric(group, "latency_avg_ms", "stdev"),
                metric(group, "latency_avg_ms", "ci95_low"), metric(group, "latency_avg_ms", "ci95_high"),
                metric(group, "latency_p50_ms"), metric(group, "latency_p95_ms"),
                metric(group, "latency_p99_ms"), metric(group, "latency_max_ms"),
                (metric(group, "error_rate") or 0.0) * 100.0,
            )
            for column, value in enumerate(values, 1):
                ws.cell(row=row, column=column, value=value)
            ws.cell(row, 2).fill = PatternFill("solid", fgColor=MODE_COLORS[mode])
            ws.cell(row, 2).font = Font(color=WHITE, bold=True)
            row += 1
    add_table(ws, 4, row - 1, len(headers), "PerformanceSummary")
    for current in ws.iter_rows(min_row=5, max_row=row - 1, min_col=5, max_col=18):
        for cell in current:
            cell.number_format = "0.000"
    for current in range(5, row):
        ws.cell(current, 9).number_format = '0.0"%";[Red]-0.0"%"'
        ws.cell(current, 18).number_format = '0.000"%"'
    ws.conditional_formatting.add(
        f"I5:I{row - 1}",
        ColorScaleRule(start_type="min", start_color=GREEN, mid_type="percentile", mid_value=50,
                       mid_color=YELLOW, end_type="max", end_color="F8696B"),
    )
    finish_sheet(ws, "A5", {"A": 19, "B": 19, "C": 7, "D": 20, "E": 18, "F": 16,
                              "G": 19, "H": 20, "I": 24, "J": 21, "K": 16, "L": 20,
                              "M": 21, "N": 12, "O": 12, "P": 12, "Q": 16, "R": 15})


def write_application_resources(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Application Resources")
    ws.sheet_properties.tabColor = "70AD47"
    headers = (
        "Workload", "Mode", "N", "App CPU mean (mCPU)", "CPU SD", "CPU CI95 low",
        "CPU CI95 high", "CPU overhead vs default (%)", "App CPU p95 (mCPU)",
        "App CPU max (mCPU)", "Estimated CPU-seconds mean", "CPU-seconds SD",
        "Estimated CPU ms/op mean", "CPU ms/op SD", "App memory mean (MiB)",
        "Memory SD (MiB)", "Memory change vs default (%)", "App memory p95 (MiB)",
        "App memory max (MiB)",
    )
    title(
        ws, "Application-container CPU and Memory",
        "workload cgroup only. CPU-seconds and CPU ms/op are estimates from sampled mean mCPU × wall time.",
        len(headers),
    )
    write_headers(ws, 4, headers)
    row = 5
    for campaign in campaigns:
        groups = groups_by_mode(campaign)
        default_cpu = metric(groups["default"], "workload_cpu_millicores_mean")
        default_memory = metric(groups["default"], "workload_memory_bytes_mean")
        for mode in MODE_ORDER:
            group = groups[mode]
            cpu_seconds = derived_stats(campaign, mode, "cpu_seconds_est") or {}
            cpu_per_op = derived_stats(campaign, mode, "cpu_ms_per_op_est") or {}
            memory_mean = metric(group, "workload_memory_bytes_mean")
            values = (
                campaign["label"], MODE_LABEL[mode], group["valid_trials"],
                metric(group, "workload_cpu_millicores_mean"),
                metric(group, "workload_cpu_millicores_mean", "stdev"),
                metric(group, "workload_cpu_millicores_mean", "ci95_low"),
                metric(group, "workload_cpu_millicores_mean", "ci95_high"),
                relative_change(metric(group, "workload_cpu_millicores_mean"), default_cpu),
                metric(group, "workload_cpu_millicores_p95"), metric(group, "workload_cpu_millicores_max"),
                cpu_seconds.get("mean"), cpu_seconds.get("stdev"),
                cpu_per_op.get("mean"), cpu_per_op.get("stdev"),
                memory_mean / 1048576.0 if memory_mean is not None else None,
                (metric(group, "workload_memory_bytes_mean", "stdev") or 0.0) / 1048576.0,
                relative_change(memory_mean, default_memory),
                (metric(group, "workload_memory_bytes_p95") or 0.0) / 1048576.0,
                (metric(group, "workload_memory_bytes_max") or 0.0) / 1048576.0,
            )
            for column, value in enumerate(values, 1):
                ws.cell(row=row, column=column, value=value)
            ws.cell(row, 2).fill = PatternFill("solid", fgColor=MODE_COLORS[mode])
            ws.cell(row, 2).font = Font(color=WHITE, bold=True)
            row += 1
    add_table(ws, 4, row - 1, len(headers), "ApplicationResources")
    for current in ws.iter_rows(min_row=5, max_row=row - 1, min_col=4, max_col=len(headers)):
        for cell in current:
            cell.number_format = "0.000"
    for current in range(5, row):
        ws.cell(current, 8).number_format = '0.0"%";[Red]-0.0"%"'
        ws.cell(current, 17).number_format = '0.0"%";[Red]-0.0"%"'
    ws.conditional_formatting.add(
        f"H5:H{row - 1}",
        ColorScaleRule(start_type="min", start_color=GREEN, mid_type="percentile", mid_value=50,
                       mid_color=YELLOW, end_type="max", end_color="F8696B"),
    )
    finish_sheet(ws, "A5", {"A": 19, "B": 19, "C": 7, "D": 21, "E": 14, "F": 16,
                              "G": 17, "H": 25, "I": 20, "J": 20, "K": 25, "L": 17,
                              "M": 25, "N": 16, "O": 22, "P": 17, "Q": 25,
                              "R": 22, "S": 22})


def write_framework_resources(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Framework Resources")
    ws.sheet_properties.tabColor = "A5A5A5"
    headers = (
        "Workload", "Mode", "N", "Framework CPU mean (mCPU)", "CPU SD", "CPU p95",
        "CPU max", "Framework memory mean (MiB)", "Memory SD", "Memory p95", "Memory max",
    )
    title(
        ws, "Framework Pod Resources",
        "주의: Kubernetes Pod metrics만 포함. host-side sygma-tracer CPU/memory는 포함되지 않아 Tetragon과 총비용 비교에 직접 사용할 수 없음.",
        len(headers),
    )
    ws["A2"].fill = PatternFill("solid", fgColor=YELLOW)
    write_headers(ws, 4, headers)
    row = 5
    for campaign in campaigns:
        groups = groups_by_mode(campaign)
        for mode in MODE_ORDER:
            group = groups[mode]
            values = (
                campaign["label"], MODE_LABEL[mode], group["valid_trials"],
                metric(group, "framework_cpu_millicores_mean"),
                metric(group, "framework_cpu_millicores_mean", "stdev"),
                metric(group, "framework_cpu_millicores_p95"), metric(group, "framework_cpu_millicores_max"),
                (metric(group, "framework_memory_bytes_mean") or 0.0) / 1048576.0,
                (metric(group, "framework_memory_bytes_mean", "stdev") or 0.0) / 1048576.0,
                (metric(group, "framework_memory_bytes_p95") or 0.0) / 1048576.0,
                (metric(group, "framework_memory_bytes_max") or 0.0) / 1048576.0,
            )
            for column, value in enumerate(values, 1):
                ws.cell(row=row, column=column, value=value)
            ws.cell(row, 2).fill = PatternFill("solid", fgColor=MODE_COLORS[mode])
            ws.cell(row, 2).font = Font(color=WHITE, bold=True)
            row += 1
    add_table(ws, 4, row - 1, len(headers), "FrameworkResources")
    for current in ws.iter_rows(min_row=5, max_row=row - 1, min_col=4, max_col=len(headers)):
        for cell in current:
            cell.number_format = "0.000"
    finish_sheet(ws, "A5", {"A": 19, "B": 19, "C": 7, "D": 26, "E": 15,
                              "F": 15, "G": 15, "H": 29, "I": 16, "J": 16, "K": 16})


def write_routes(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("SYGMA Routes")
    ws.sheet_properties.tabColor = "5B9BD5"
    headers = (
        "Workload", "Mode", "N", "Conventional mean", "Conventional share (%)",
        "LSM-BPF mean", "LSM share (%)", "Ptrace-notify mean", "Ptrace share (%)",
        "Total mean", "Total SD", "Total CI95 low", "Total CI95 high",
        "LSM hits/sec", "Ptrace hits/sec",
    )
    title(
        ws, "SYGMA Policy-decision Route Counters",
        "Route hits, not denials or delivered SIGKILLs. All-trace counters do not equal total seccomp stops.",
        len(headers),
    )
    write_headers(ws, 4, headers)
    row = 5
    for campaign in campaigns:
        groups = groups_by_mode(campaign)
        for mode in ("sygma", "sygma-all-trace"):
            group = groups[mode]
            values = (
                campaign["label"], MODE_LABEL[mode], group["valid_trials"],
                metric(group, "route_conventional_sigkill_count"),
                route_share(group, "conventional_sigkill"),
                metric(group, "route_lsm_bpf_count"), route_share(group, "lsm_bpf"),
                metric(group, "route_ptrace_notify_count"), route_share(group, "ptrace_notify"),
                metric(group, "route_total_count"), metric(group, "route_total_count", "stdev"),
                metric(group, "route_total_count", "ci95_low"), metric(group, "route_total_count", "ci95_high"),
                metric(group, "route_lsm_bpf_per_second"), metric(group, "route_ptrace_notify_per_second"),
            )
            for column, value in enumerate(values, 1):
                ws.cell(row=row, column=column, value=value)
            ws.cell(row, 2).fill = PatternFill("solid", fgColor=MODE_COLORS[mode])
            ws.cell(row, 2).font = Font(color=WHITE, bold=True)
            row += 1
    add_table(ws, 4, row - 1, len(headers), "SygmaRoutes")
    for current in ws.iter_rows(min_row=5, max_row=row - 1, min_col=4, max_col=len(headers)):
        for cell in current:
            cell.number_format = "0.000"
    for current in range(5, row):
        for column in (5, 7, 9):
            ws.cell(current, column).number_format = '0.00"%"'
    for column in ("E", "G", "I"):
        ws.conditional_formatting.add(
            f"{column}5:{column}{row - 1}",
            DataBarRule(start_type="num", start_value=0, end_type="num", end_value=100,
                        color="5B9BD5", showValue=True),
        )
    finish_sheet(ws, "A5", {"A": 19, "B": 19, "C": 7, "D": 20, "E": 23,
                              "F": 18, "G": 17, "H": 21, "I": 20, "J": 16,
                              "K": 15, "L": 18, "M": 19, "N": 17, "O": 19})


def write_trials(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Trial Data")
    ws.sheet_properties.tabColor = "8064A2"
    headers = (
        "Campaign", "Workload", "Mode", "Repetition", "Sequence", "Valid",
        "Operations", "Errors", "Error rate (%)", "Throughput ops/s", "Wall seconds",
        "Avg latency ms", "p50 ms", "p95 ms", "p99 ms", "Max latency ms",
        "App CPU mean mCPU", "App CPU p95", "App CPU max", "Estimated app CPU-seconds",
        "Estimated app CPU ms/op", "App memory mean MiB", "Framework CPU mean mCPU",
        "Framework memory mean MiB", "Node CPU mean mCPU", "Node memory mean GiB",
        "Conventional route", "LSM route", "Ptrace route", "Route total", "Invalid reason",
    )
    title(ws, "Valid Trial-level Data", "One row per trial; includes derived application CPU-time estimates.", len(headers))
    write_headers(ws, 4, headers)
    row = 5
    for campaign in campaigns:
        ordered = sorted(campaign["trials"], key=lambda trial: int(trial.get("sequence", 0)))
        for trial in ordered:
            performance = trial.get("performance") or {}
            scopes = ((trial.get("resources") or {}).get("scopes") or {})
            app = scopes.get("workload") or {}
            framework = scopes.get("framework") or {}
            node = scopes.get("node") or {}
            routes = trial.get("routes") or {}
            derived = trial_derived(trial)
            values = (
                campaign["path"].name, campaign["label"], MODE_LABEL.get(trial.get("mode"), trial.get("mode")),
                trial.get("repetition"), trial.get("sequence"), bool(trial.get("valid")),
                derived["operations"], performance.get("errors", 0), float(trial.get("error_rate") or 0.0) * 100.0,
                performance.get("throughput_ops_per_sec"), performance.get("wall_seconds"),
                performance.get("latency_avg_ms"), performance.get("latency_p50_ms"),
                performance.get("latency_p95_ms"), performance.get("latency_p99_ms"),
                performance.get("latency_max_ms"), app.get("cpu_millicores_mean"),
                app.get("cpu_millicores_p95"), app.get("cpu_millicores_max"),
                derived["cpu_seconds_est"], derived["cpu_ms_per_op_est"],
                app.get("memory_bytes_mean", 0) / 1048576.0,
                framework.get("cpu_millicores_mean", 0),
                framework.get("memory_bytes_mean", 0) / 1048576.0,
                node.get("cpu_millicores_mean"), node.get("memory_bytes_mean", 0) / 1073741824.0,
                routes.get("conventional_sigkill"), routes.get("lsm_bpf"), routes.get("ptrace_notify"),
                routes.get("total"), trial.get("invalid_reason", ""),
            )
            for column, value in enumerate(values, 1):
                ws.cell(row=row, column=column, value=value)
            mode = str(trial.get("mode"))
            ws.cell(row, 3).fill = PatternFill("solid", fgColor=MODE_COLORS.get(mode, "808080"))
            ws.cell(row, 3).font = Font(color=WHITE, bold=True)
            row += 1
    add_table(ws, 4, row - 1, len(headers), "TrialData")
    for current in ws.iter_rows(min_row=5, max_row=row - 1, min_col=9, max_col=26):
        for cell in current:
            cell.number_format = "0.000"
    for current in range(5, row):
        ws.cell(current, 9).number_format = '0.000"%"'
    widths = {"A": 46, "B": 19, "C": 19, "D": 11, "E": 10, "F": 9,
              "G": 14, "H": 11, "I": 15, "J": 18, "K": 15, "L": 17,
              "M": 12, "N": 12, "O": 12, "P": 15, "Q": 20, "R": 15,
              "S": 15, "T": 25, "U": 24, "V": 21, "W": 25, "X": 27,
              "Y": 20, "Z": 21, "AA": 19, "AB": 16, "AC": 16, "AD": 15,
              "AE": 42}
    finish_sheet(ws, "A5", widths)


def write_setup(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Experiment Setup")
    ws.sheet_properties.tabColor = "A9D08E"
    headers = (
        "Workload", "Campaign", "Topology", "Node", "Modes", "Repetitions",
        "Duration s", "Warm-up s", "Cooldown s", "Metrics interval s", "Min samples",
        "HTTP rate", "HTTP connections", "HTTP threads", "Hotel rate",
        "Redis requests", "Redis clients", "MySQL threads", "MySQL events",
        "MySQL tables", "MySQL table size", "Max error rate", "Seed", "Randomized",
        "Summary JSON", "Trials JSONL",
    )
    title(ws, "Experiment Configuration and Provenance", "Arguments are read from each campaign metadata.json.", len(headers))
    write_headers(ws, 4, headers)
    row = 5
    for campaign in campaigns:
        args = campaign["metadata"].get("arguments") or {}
        values = (
            campaign["label"], campaign["path"].name, args.get("topology"), args.get("workload_node"),
            args.get("modes"), args.get("repetitions"), args.get("duration"), args.get("warmup"),
            args.get("cooldown"), args.get("metrics_interval"), args.get("minimum_metric_samples"),
            args.get("http_rate"), args.get("http_connections"), args.get("http_threads"),
            args.get("hotel_rate"), args.get("redis_requests"), args.get("redis_clients"),
            args.get("mysql_threads"), args.get("mysql_events", 0), args.get("mysql_tables"),
            args.get("mysql_table_size"), args.get("max_error_rate"), args.get("seed"),
            bool(args.get("randomize")), str(campaign["path"] / "summary.json"),
            str(campaign["path"] / "trials.jsonl"),
        )
        for column, value in enumerate(values, 1):
            ws.cell(row=row, column=column, value=value)
        for column, filename in ((25, "summary.json"), (26, "trials.jsonl")):
            ws.cell(row, column).hyperlink = (campaign["path"] / filename).as_uri()
            ws.cell(row, column).style = "Hyperlink"
        row += 1
    add_table(ws, 4, row - 1, len(headers), "ExperimentSetup")

    image_row = row + 3
    write_headers(ws, image_row, ("Campaign", "Image reference", "Resolved image ID"))
    image_start = image_row + 1
    for campaign in campaigns:
        for image_ref, image_ids in sorted(campaign["summary"].get("resolved_image_ids", {}).items()):
            for image_id in image_ids:
                image_row += 1
                ws.cell(image_row, 1, campaign["path"].name)
                ws.cell(image_row, 2, image_ref)
                ws.cell(image_row, 3, image_id)
    add_table(ws, image_start - 1, image_row, 3, "ResolvedImages")
    widths = {"A": 19, "B": 47, "C": 12, "D": 13, "E": 10, "F": 14,
              "G": 12, "H": 12, "I": 12, "J": 18, "K": 14, "L": 12,
              "M": 18, "N": 14, "O": 13, "P": 18, "Q": 14, "R": 15,
              "S": 15, "T": 14, "U": 17, "V": 16, "W": 12, "X": 13,
              "Y": 70, "Z": 70}
    finish_sheet(ws, "A5", widths)


def style_chart(chart: BarChart, title_text: str, y_title: str, modes: tuple[str, ...]) -> None:
    chart.title = title_text
    chart.y_axis.title = y_title
    chart.x_axis.title = "Workload"
    chart.height = 9
    chart.width = 16
    chart.style = 10
    chart.legend.position = "b"
    chart.dLbls = DataLabelList()
    chart.dLbls.showVal = False
    for series, mode in zip(chart.series, modes):
        series.graphicalProperties.solidFill = MODE_COLORS[mode]
        series.graphicalProperties.line.solidFill = MODE_COLORS[mode]


def write_charts(wb: Workbook, campaigns: list[dict[str, Any]]) -> None:
    ws = wb.create_sheet("Charts")
    ws.sheet_properties.tabColor = "ED7D31"
    title(ws, "Benchmark Charts", "Positive values indicate overhead/degradation relative to Default.", 18)

    modes = ("tetragon", "sygma", "sygma-all-trace")
    write_headers(ws, 4, ("Workload", *(MODE_LABEL[mode] for mode in modes)))
    for index, campaign in enumerate(campaigns, 5):
        ws.cell(index, 1, campaign["label"])
        for column, mode in enumerate(modes, 2):
            ws.cell(index, column, degradation(campaign, mode))
            ws.cell(index, column).number_format = '0.0"%"'

    write_headers(ws, 4, ("Workload", *(MODE_LABEL[mode] for mode in modes)))
    cpu_start_column = 7
    for column, header in enumerate(("Workload", *(MODE_LABEL[mode] for mode in modes)), cpu_start_column):
        cell = ws.cell(4, column, header)
        cell.font = Font(bold=True, color=WHITE)
        cell.fill = PatternFill("solid", fgColor=NAVY)
    for index, campaign in enumerate(campaigns, 5):
        groups = groups_by_mode(campaign)
        default = metric(groups["default"], "workload_cpu_millicores_mean")
        ws.cell(index, cpu_start_column, campaign["label"])
        for column, mode in enumerate(modes, cpu_start_column + 1):
            ws.cell(index, column, relative_change(metric(groups[mode], "workload_cpu_millicores_mean"), default))
            ws.cell(index, column).number_format = '0.0"%"'

    cpu_op_start = 13
    for column, header in enumerate(("Workload", *(MODE_LABEL[mode] for mode in modes)), cpu_op_start):
        cell = ws.cell(4, column, header)
        cell.font = Font(bold=True, color=WHITE)
        cell.fill = PatternFill("solid", fgColor=NAVY)
    for index, campaign in enumerate(campaigns, 5):
        default_stats = derived_stats(campaign, "default", "cpu_ms_per_op_est") or {}
        default = default_stats.get("mean")
        ws.cell(index, cpu_op_start, campaign["label"])
        for column, mode in enumerate(modes, cpu_op_start + 1):
            current = (derived_stats(campaign, mode, "cpu_ms_per_op_est") or {}).get("mean")
            ws.cell(index, column, relative_change(current, default))
            ws.cell(index, column).number_format = '0.0"%"'

    chart = BarChart()
    chart.type = "col"
    chart.add_data(Reference(ws, min_col=2, max_col=4, min_row=4, max_row=11), titles_from_data=True)
    chart.set_categories(Reference(ws, min_col=1, min_row=5, max_row=11))
    style_chart(chart, "Performance degradation vs Default", "Degradation (%)", modes)
    ws.add_chart(chart, "A14")

    cpu_chart = BarChart()
    cpu_chart.type = "col"
    cpu_chart.add_data(Reference(ws, min_col=8, max_col=10, min_row=4, max_row=11), titles_from_data=True)
    cpu_chart.set_categories(Reference(ws, min_col=7, min_row=5, max_row=11))
    style_chart(cpu_chart, "Application CPU rate overhead", "CPU overhead (%)", modes)
    ws.add_chart(cpu_chart, "J14")

    cpu_op_chart = BarChart()
    cpu_op_chart.type = "col"
    cpu_op_chart.add_data(Reference(ws, min_col=14, max_col=16, min_row=4, max_row=11), titles_from_data=True)
    cpu_op_chart.set_categories(Reference(ws, min_col=13, min_row=5, max_row=11))
    style_chart(cpu_op_chart, "Estimated application CPU time per operation", "CPU ms/op overhead (%)", modes)
    ws.add_chart(cpu_op_chart, "A33")

    route_start = 52
    route_headers = ("Workload", "Conventional", "LSM-BPF", "Ptrace-notify")
    for column, header in enumerate(route_headers, 1):
        cell = ws.cell(route_start, column, header)
        cell.font = Font(bold=True, color=WHITE)
        cell.fill = PatternFill("solid", fgColor=NAVY)
    for index, campaign in enumerate(campaigns, route_start + 1):
        group = groups_by_mode(campaign)["sygma"]
        ws.cell(index, 1, campaign["label"])
        ws.cell(index, 2, route_share(group, "conventional_sigkill"))
        ws.cell(index, 3, route_share(group, "lsm_bpf"))
        ws.cell(index, 4, route_share(group, "ptrace_notify"))
    route_chart = BarChart()
    route_chart.type = "bar"
    route_chart.grouping = "stacked"
    route_chart.overlap = 100
    route_chart.add_data(
        Reference(ws, min_col=2, max_col=4, min_row=route_start, max_row=route_start + len(campaigns)),
        titles_from_data=True,
    )
    route_chart.set_categories(
        Reference(ws, min_col=1, min_row=route_start + 1, max_row=route_start + len(campaigns))
    )
    route_chart.title = "Selective SYGMA route share"
    route_chart.x_axis.title = "Share (%)"
    route_chart.height = 9
    route_chart.width = 16
    route_chart.legend.position = "b"
    for series, color in zip(route_chart.series, ("A5A5A5", "4472C4", "ED7D31")):
        series.graphicalProperties.solidFill = color
    ws.add_chart(route_chart, "J33")

    finish_sheet(ws, "A5", {"A": 19, "B": 18, "C": 18, "D": 20, "G": 19,
                              "H": 18, "I": 18, "J": 20, "M": 19, "N": 18,
                              "O": 18, "P": 20})


def build(output: Path) -> None:
    campaigns = [select_campaign(*spec) for spec in CAMPAIGN_SPECS]
    wb = Workbook()
    wb.properties.title = "SYGMA Q3 Final Benchmark Results"
    wb.properties.subject = "Runtime performance, resources, and route ratios"
    wb.properties.creator = "SYGMA performance-eval benchmark"
    wb.properties.description = "Generated from valid final campaign JSON outputs."

    write_overview(wb, campaigns)
    write_performance(wb, campaigns)
    write_application_resources(wb, campaigns)
    write_framework_resources(wb, campaigns)
    write_routes(wb, campaigns)
    write_trials(wb, campaigns)
    write_setup(wb, campaigns)
    write_charts(wb, campaigns)

    output.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output)

    # Fail immediately if a malformed workbook was produced.
    checked = load_workbook(output, read_only=False, data_only=False)
    expected_sheets = {
        "Overview", "Performance", "Application Resources", "Framework Resources",
        "SYGMA Routes", "Trial Data", "Experiment Setup", "Charts",
    }
    if set(checked.sheetnames) != expected_sheets:
        raise RuntimeError(f"unexpected workbook sheets: {checked.sheetnames}")
    if checked["Trial Data"].max_row != 64:
        raise RuntimeError(f"expected 60 trial rows, got {checked['Trial Data'].max_row - 4}")
    checked.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=RESULTS / "sygma-q3-final-results-20260818.xlsx",
    )
    args = parser.parse_args()
    build(args.output.resolve())
    print(args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
