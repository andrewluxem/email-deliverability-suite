"""Self-contained HTML for ``deliv report``: inline CSS, no scripts, no external assets."""

from html import escape
from typing import Any

from deliv.report import TOOL_TITLES, headline, result_label

_CSS = """
:root { --bg:#f7f7f5; --card:#ffffff; --ink:#1d1d1f; --muted:#5f6368; --line:#e3e3df;
  --pass:#1e7d45; --pass-bg:#e5f4ea; --warn:#8a5a00; --warn-bg:#fff3d6; --fail:#b3261e;
  --fail-bg:#fde7e5; --info:#1f5fa8; --info-bg:#e6eef9; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#141416; --card:#1d1d20; --ink:#ececef; --muted:#a2a2aa; --line:#303036;
    --pass:#6fd39a; --pass-bg:#16301f; --warn:#f0c46a; --warn-bg:#35290f; --fail:#ff8a80;
    --fail-bg:#3a1714; --info:#8ab8f5; --info-bg:#172537; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
  font:15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial,
  sans-serif; }
main { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
h1 { font-size: 28px; margin: 0 0 4px; }
h2 { font-size: 20px; margin: 36px 0 12px; }
.meta, .muted { color: var(--muted); font-size: 13px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 20px;
  margin-top: 16px; }
.hero { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
.grade { font-size: 56px; font-weight: 700; line-height: 1; min-width: 72px; text-align: center; }
.grade-A, .grade-B { color: var(--pass); } .grade-C, .grade-D { color: var(--warn); }
.grade-F { color: var(--fail); }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
.table-wrap { overflow-x: auto; }
.pill { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px;
  font-weight: 600; white-space: nowrap; }
.pill-pass { color: var(--pass); background: var(--pass-bg); }
.pill-warn { color: var(--warn); background: var(--warn-bg); }
.pill-fail { color: var(--fail); background: var(--fail-bg); }
.pill-info { color: var(--info); background: var(--info-bg); }
ol.fixes { padding-left: 22px; margin: 0; }
ol.fixes li { margin: 0 0 12px; }
.fix { color: var(--muted); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
.flush { margin: 0 0 4px; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; }
"""


def _e(value: Any) -> str:
    return escape(str(value if value is not None else ""))


def _pill(status: str) -> str:
    label = {"pass": "PASS", "warn": "WARN", "fail": "FAIL", "info": "INFO"}.get(status, status)
    return f'<span class="pill pill-{_e(status)}">{_e(label)}</span>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return (
        f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def _extras(result: dict[str, Any]) -> str:
    tool = result["tool"]
    parts: list[str] = []
    if tool in {"spam-scan", "copy-check"} and result.get("rewrites"):
        items = "".join(
            f'<li>&ldquo;{_e(r["found"])}&rdquo; <span class="muted">({_e(r["field"])}, line '
            f"{_e(r['line'])})</span>: {_e(r['rewrite'])}</li>"
            for r in result["rewrites"]
        )
        parts.append(f"<h3>Suggested rewrites</h3><ol>{items}</ol>")
    if tool == "header-analyze":
        a = result.get("alignment", {})
        parts.append(
            "<p>"
            f"Sending IP: <code>{_e(result.get('sending_ip') or 'unknown')}</code><br>"
            f"From domain: <code>{_e(a.get('from_domain'))}</code>, envelope-from: "
            f"<code>{_e(a.get('envelope_from_domain'))}</code>, alignment: "
            f"<strong>{_e(a.get('verdict'))}</strong><br>"
            f"Diagnosis: {_e(result.get('diagnosis'))}</p>"
        )
    if tool == "bounce-classify":
        rows = result.get("results") or [result]
        parts.append(
            _table(
                ["Class", "Action", "Code", "Rule"],
                [
                    [_e(r.get("classification")), _e(r.get("action")),
                     _e(r.get("status_code") or r.get("smtp_code") or "-"),
                     f"<code>{_e(r.get('rule', {}).get('id'))}</code>"]
                    for r in rows
                ],
            )
        )  # fmt: skip
    if tool == "warmup-plan" and result.get("plan"):
        parts.append(f"<p><em>{_e(result.get('disclaimer'))}</em></p>")
        parts.append(
            _table(
                ["Day", "Volume", "Send to"],
                [[_e(d["day"]), _e(f"{d['volume']:,}"), _e(d["audience"])] for d in result["plan"]],
            )
        )
    return "".join(parts)


def render_html_document(report: dict[str, Any]) -> str:
    """Build the full HTML document for a report model from :func:`deliv.report.build_report`."""
    overall = report["overall_grade"] or "-"
    summary_rows = [
        [_e(r["tool_title"]), f"<code>{_e(r['target'])}</code>", _pill(r["status"]) + " " +
         _e(r["result"]), _e(r["summary"])]
        for r in report["summary_rows"]
    ]  # fmt: skip
    if report["fixes"]:
        fixes = "".join(
            f"<li>{_pill(f['status'])} <strong>{_e(f['check'])}</strong> "
            f'<span class="muted">({_e(f["tool_title"])}, {_e(f["target"])})</span><br>'
            f'{_e(f["problem"])}<br><span class="fix">Fix: {_e(f["fix"])}</span></li>'
            for f in report["fixes"]
        )
        fixes_html = f'<ol class="fixes">{fixes}</ol>'
    else:
        fixes_html = "<p>Nothing to fix. Every check passed.</p>"

    sections = []
    for result in report["sections"]:
        findings = result.get("findings", [])
        table = _table(
            ["Status", "Check", "Finding", "Fix"],
            [
                [_pill(f["status"]), _e(f.get("check")), _e(f.get("message")),
                 _e(f.get("remediation")) if f["status"] != "pass" else ""]
                for f in findings
            ],
        ) if findings else ""  # fmt: skip
        sections.append(
            f'<section class="card"><h2>{_e(TOOL_TITLES[result["tool"]])}: '
            f"<code>{_e(result.get('target'))}</code></h2>"
            f"<p><strong>{_e(result_label(result))}.</strong> {_e(result.get('summary'))}</p>"
            f"{table}{_extras(result)}</section>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(report["title"])}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<h1>{_e(report["title"])}</h1>
<p class="meta">Generated {_e(report["generated_at"])} by deliv {_e(report["deliv_version"])}</p>
<section class="card hero">
<div class="grade grade-{_e(overall)}">{_e(overall)}</div>
<div><h2 class="flush">Executive summary</h2><p class="flush">{_e(headline(report))}</p></div>
</section>
<section class="card">{_table(["Check", "Target", "Result", "Summary"], summary_rows)}</section>
<h2>Prioritized fix list</h2>
<section class="card">{fixes_html}</section>
{"".join(sections)}
<footer>Findings are automated checks and heuristics. Grades describe configuration and content
risk; they do not guarantee inbox placement.</footer>
</main>
</body>
</html>
"""
