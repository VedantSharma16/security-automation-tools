"""Human-readable rendering of campaign and guard-evaluation results."""

from __future__ import annotations

_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}

REMEDIATION = {
    "direct_injection": "Enforce an instruction hierarchy (system > user), screen user input, and never let output-forcing requests change task scope.",
    "indirect_injection": "Treat retrieved content as untrusted data: spotlight/delimit it, scan it before it reaches the model, and never execute instructions found in it.",
    "prompt_leak": "Assume the system prompt is public. Move secrets out of it entirely and add an output filter for prompt overlap.",
    "secret_exfiltration": "Never place credentials in model context. Use server-side tool calls with scoped tokens; filter outputs for secrets in encoded forms.",
    "jailbreak": "Add persona/jailbreak detection on input and keep safety rules outside the user-modifiable context.",
    "obfuscation": "Normalize input (Unicode NFKC, homoglyph folding, zero-width stripping, base64 decoding) before any filtering; cover non-English phrasing.",
}


def render_markdown(campaign: dict) -> str:
    s = campaign["summary"]
    lines = [
        f"# LLM red-team report — `{campaign['target']}`",
        "",
        f"*Run started {campaign['started_at']}*",
        "",
        f"**Attack success rate:** {s['attack_success_rate']:.0%} "
        f"({s['succeeded']}/{s['completed']} completed attacks; {s['errors']} errors)  ",
        f"**Worst successful severity:** {_ICON.get(s['worst_severity'], '')} {s['worst_severity'].upper()}",
        "",
        "## By OWASP LLM Top 10 category",
        "",
        "| ID | Risk | Succeeded / Attempted | ASR |",
        "|---|---|---|---|",
    ]
    for oid, b in campaign["by_owasp"].items():
        lines.append(f"| {oid} | {b.get('title', '')} | {b['succeeded']}/{b['attempted']} | {b['asr']:.0%} |")

    lines += ["", "## By attack technique", "", "| Category | Succeeded / Attempted | ASR |", "|---|---|---|"]
    for cat, b in campaign["by_category"].items():
        lines.append(f"| {cat} | {b['succeeded']}/{b['attempted']} | {b['asr']:.0%} |")

    lines += ["", "## Results", "", "| | ID | Attack | Delivery | Result | Evidence |", "|---|---|---|---|---|---|"]
    for r in campaign["results"]:
        status = "ERROR" if r["error"] else ("**VULNERABLE**" if r["success"] else ("refused" if r["refused"] else "resisted"))
        icon = _ICON.get(r["severity"], "") if r["success"] else ""
        evidence = (r["error"] or r["evidence"]).replace("|", "\\|")
        lines.append(f"| {icon} | {r['attack_id']} | {r['name']} | {r['delivery']} | {status} | {evidence} |")

    failed_cats = sorted({r["category"] for r in campaign["results"] if r["success"]})
    if failed_cats:
        lines += ["", "## Recommended remediation", ""]
        for cat in failed_cats:
            lines.append(f"- **{cat}** — {REMEDIATION.get(cat, 'Review and harden.')}")

    if campaign.get("defence_events"):
        lines += ["", "## Defence telemetry", ""]
        lines += [f"- {e}" for e in campaign["defence_events"]]

    return "\n".join(lines) + "\n"


def render_console(campaign: dict) -> str:
    s = campaign["summary"]
    lines = [
        f"Target: {campaign['target']}",
        f"Attack success rate: {s['attack_success_rate']:.0%} ({s['succeeded']}/{s['completed']}), "
        f"worst severity: {_ICON.get(s['worst_severity'], '')} {s['worst_severity'].upper()}",
        "",
    ]
    for r in campaign["results"]:
        if r["error"]:
            mark = "ERR "
        elif r["success"]:
            mark = "VULN"
        else:
            mark = "ok  "
        lines.append(f"  [{mark}] {r['attack_id']:<7} {r['category']:<20} {r['name']}  — {r['error'] or r['evidence']}")
    return "\n".join(lines)


def render_comparison(campaigns: list[dict]) -> str:
    header = "| Attack | " + " | ".join(c["target"] for c in campaigns) + " |"
    sep = "|---|" + "---|" * len(campaigns)
    rows = [header, sep]
    for idx, r in enumerate(campaigns[0]["results"]):
        cells = []
        for c in campaigns:
            res = c["results"][idx]
            cells.append("ERR" if res["error"] else ("VULN" if res["success"] else "ok"))
        rows.append(f"| {r['attack_id']} {r['name']} | " + " | ".join(cells) + " |")
    rows.append("| **Attack success rate** | " + " | ".join(f"**{c['summary']['attack_success_rate']:.0%}**" for c in campaigns) + " |")
    return "\n".join(rows)


def render_guard_metrics(metrics: list[dict]) -> str:
    lines = ["| Normalization | Threshold | Precision | Recall | F1 | FPR | TP | FP | TN | FN |", "|---|---|---|---|---|---|---|---|---|---|"]
    for m in metrics:
        c = m["confusion"]
        lines.append(
            f"| {'on' if m['normalization'] else 'off'} | {m['threshold']} | {m['precision']:.2f} | {m['recall']:.2f} | "
            f"{m['f1']:.2f} | {m['false_positive_rate']:.2f} | {c['tp']} | {c['fp']} | {c['tn']} | {c['fn']} |"
        )
    for m in metrics:
        label = "with" if m["normalization"] else "without"
        if m["false_negatives"]:
            lines.append(f"\nMissed attacks ({label} normalization): {', '.join(m['false_negatives'])}")
        if m["false_positives"]:
            lines.append(f"False positives ({label} normalization):")
            lines += [f"  - {t}" for t in m["false_positives"]]
    return "\n".join(lines)
