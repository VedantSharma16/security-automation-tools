"""Anthropic-format tool schemas exposed to the agent's tool-use loop.

``FINAL_REPORT_TOOL`` is handled specially: when the model calls it, the
agent loop treats that as the signal to stop investigating and parses its
arguments as the final verdict, rather than executing a Python function and
feeding a result back in.
"""

from __future__ import annotations

INVESTIGATION_TOOLS = [
    {
        "name": "extract_iocs",
        "description": (
            "Extract IP addresses, domains, and file hashes from a block of "
            "free-text alert or log content. Handles defanged indicators "
            "(e.g. 185[.]220[.]101[.]45, hxxp://)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Raw alert or log text to scan."},
            },
            "required": ["text"],
        },
    },
    {
        "name": "check_threat_intel",
        "description": (
            "Look up a single indicator (IP, domain, or hash) against the local "
            "threat-intel feed to see if it is known-malicious."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The indicator value, e.g. '185.220.101.45'."},
                "category": {"type": "string", "enum": ["ip", "domain", "hash"]},
            },
            "required": ["indicator", "category"],
        },
    },
    {
        "name": "analyze_auth_log",
        "description": (
            "Run correlated rule-based detection over auth-log style text: "
            "brute-force attempts, likely credential compromise, and "
            "privilege escalation via sudo."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "log_text": {"type": "string", "description": "Raw auth.log-style text."},
            },
            "required": ["log_text"],
        },
    },
    {
        "name": "check_process_list",
        "description": (
            "Check a list of running process command lines against a ruleset "
            "of known-suspicious patterns (reverse shells, encoded PowerShell, "
            "credential dumping tools, cron persistence, privilege escalation)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "processes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of process command lines observed on the host.",
                },
            },
            "required": ["processes"],
        },
    },
    {
        "name": "lookup_mitre_technique",
        "description": "Look up the name, tactic, and description of a MITRE ATT&CK technique by id.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "e.g. 'T1110'."},
            },
            "required": ["technique_id"],
        },
    },
]

FINAL_REPORT_TOOL = {
    "name": "submit_final_report",
    "description": (
        "Conclude the investigation and submit the final structured verdict. "
        "Call this only after you have gathered enough evidence with the other "
        "tools — do not call it as your first action."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
            },
            "summary": {
                "type": "string",
                "description": "2-4 sentence analyst summary of what happened and why it matters.",
            },
            "technique_ids": {
                "type": "array",
                "items": {"type": "string"},
                "description": "MITRE ATT&CK technique ids supported by the evidence gathered.",
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "2-4 concrete next steps for the on-call analyst.",
            },
        },
        "required": ["severity", "summary", "technique_ids", "recommended_actions"],
    },
}

ALL_TOOLS = INVESTIGATION_TOOLS + [FINAL_REPORT_TOOL]
