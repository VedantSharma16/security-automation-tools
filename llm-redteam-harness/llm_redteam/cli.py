"""Command-line entry point: ``llm-redteam {run,compare,scan,list}``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .guardrails import GuardedTarget, GuardrailConfig, InjectionClassifier
from .probes import load_benign, load_probes
from .report import render_ablation, render_comparison, render_markdown
from .runner import ablation, new_scenario, run
from .targets import DEFAULT_MODEL, AnthropicTarget, NaiveModel


def _build_inner(args):
    if args.target == "anthropic":
        return AnthropicTarget(model=args.model)
    return NaiveModel()


def _write(path: str | None, content: str) -> None:
    if path:
        Path(path).write_text(content)


def cmd_run(args) -> int:
    scenario = new_scenario()
    probes = load_probes(Path(args.probes) if args.probes else None).filter(args.category)
    benign = load_benign()
    target = _build_inner(args)
    if args.guardrails:
        target = GuardedTarget(target, scenario, GuardrailConfig(threshold=args.threshold))
    result = run(target, probes, scenario, benign)
    md = render_markdown(result)
    print(json.dumps(result.to_dict(), indent=2) if args.json else md)
    _write(args.md_out, md)
    _write(args.json_out, json.dumps(result.to_dict(), indent=2))
    return 1 if result.attack_success_rate() > args.fail_above else 0


def cmd_compare(args) -> int:
    scenario = new_scenario()
    probes = load_probes(Path(args.probes) if args.probes else None).filter(args.category)
    benign = load_benign()
    inner = _build_inner(args)
    baseline = run(inner, probes, scenario, benign)
    guarded = run(GuardedTarget(inner, scenario, GuardrailConfig(threshold=args.threshold)), probes, scenario, benign)
    md = render_comparison(baseline, guarded)
    print(md)
    _write(args.md_out, md + "\n" + render_markdown(guarded))
    _write(args.json_out, json.dumps({"baseline": baseline.to_dict(), "guarded": guarded.to_dict()}, indent=2))
    return 1 if guarded.attack_success_rate() > args.fail_above else 0


def cmd_ablation(args) -> int:
    scenario = new_scenario()
    probes = load_probes(Path(args.probes) if args.probes else None).filter(args.category)
    results = ablation(_build_inner(args), probes, scenario, load_benign())
    md = render_ablation(results)
    print(md)
    _write(args.md_out, md)
    _write(args.json_out, json.dumps({k: v.summary() for k, v in results.items()}, indent=2))
    return 0


def cmd_scan(args) -> int:
    text = args.text if args.text != "-" else sys.stdin.read()
    verdict = InjectionClassifier(threshold=args.threshold).classify(text)
    label = "INJECTION" if verdict.is_injection(args.threshold) else "clean"
    print(json.dumps({"label": label, "score": verdict.score, "rules": verdict.rules}, indent=2))
    return 1 if label == "INJECTION" else 0


def cmd_list(args) -> int:
    for p in load_probes().probes:
        print(f"{p.id:8} {p.category:20} {','.join(p.owasp):12} {p.technique}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llm-redteam", description="Prompt-injection red teaming + guardrails for LLM apps.")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("--target", choices=["naive", "anthropic"], default="naive",
                       help="naive = deterministic vulnerable simulator (default); anthropic = live Claude model")
        p.add_argument("--model", default=DEFAULT_MODEL)
        p.add_argument("--probes", help="path to a custom probes JSON file")
        p.add_argument("--category", action="append", help="only run this category (repeatable)")
        p.add_argument("--threshold", type=float, default=0.5, help="injection classifier threshold")
        p.add_argument("--fail-above", type=float, default=0.0,
                       help="exit 1 if attack success rate exceeds this (CI gate)")
        p.add_argument("--md-out")
        p.add_argument("--json-out")

    p_run = sub.add_parser("run", help="run the probe corpus against one target")
    add_common(p_run)
    p_run.add_argument("--guardrails", action="store_true", help="wrap the target in GuardedTarget")
    p_run.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    p_run.set_defaults(func=cmd_run)

    p_cmp = sub.add_parser("compare", help="run baseline and guarded, report the ASR delta")
    add_common(p_cmp)
    p_cmp.set_defaults(func=cmd_compare)

    p_abl = sub.add_parser("ablation", help="measure each guardrail layer in isolation")
    add_common(p_abl)
    p_abl.set_defaults(func=cmd_ablation)

    p_scan = sub.add_parser("scan", help="classify a single piece of text ('-' for stdin)")
    p_scan.add_argument("text")
    p_scan.add_argument("--threshold", type=float, default=0.5)
    p_scan.set_defaults(func=cmd_scan)

    sub.add_parser("list", help="list available probes").set_defaults(func=cmd_list)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
