"""Tool schemas (Anthropic tool-use / JSON Schema format) for every tool the
agent can call, plus the terminal ``submit_incident_report`` tool the model
must call to end the investigation with a structured verdict.

Keeping these separate from the tool implementations in ``tools/`` mirrors
how you'd structure a real agent: the schema is the contract the LLM sees,
the implementation is plain Python the LLM never touches directly.
"""

from __future__ import annotations

EXTRACT_IOCS_TOOL = {
    "name": "extract_iocs",
    "description": (
        "Extract indicators of compromise (IPs, domains, URLs, emails, file "
        "hashes, CVE IDs) from a block of raw incident text. Handles "
        "defanged indicators (e.g. 185[.]220[.]101[.]45, hxxps://). Call this "
        "first on any incident text that might contain indicators."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Raw incident text to scan for IOCs."},
        },
        "required": ["text"],
    },
}

ENRICH_INDICATORS_TOOL = {
    "name": "enrich_indicators",
    "description": (
        "Check previously-extracted IOCs against a local threat-intel feed of "
        "known-malicious indicators. Call this after extract_iocs, passing "
        "along its output, to learn which indicators are already known-bad."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "indicators": {
                "type": "object",
                "description": "The exact object returned by extract_iocs.",
            },
        },
        "required": ["indicators"],
    },
}

ANALYZE_AUTH_LOG_TOOL = {
    "name": "analyze_auth_log",
    "description": (
        "Analyze raw Linux auth-log / sshd-style log lines for brute-force "
        "login attempts, successful logins that follow brute-force from the "
        "same IP (likely compromise), sudo/privilege-escalation activity, "
        "and persistence mechanisms (new user accounts, crontab edits). Only "
        "call this if the incident text actually contains log lines."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "text": {"type": "string", "description": "Raw log text to analyze."},
        },
        "required": ["text"],
    },
}

MAP_ATTACK_TECHNIQUES_TOOL = {
    "name": "map_attack_techniques",
    "description": (
        "Map incident context (a description, or a summary of what the other "
        "tools found) to the most relevant MITRE ATT&CK techniques via "
        "keyword scoring. Call this once you have enough context — e.g. "
        "after log analysis and enrichment — to describe what happened."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "Text describing observed behavior to map to ATT&CK techniques.",
            },
            "top_k": {
                "type": "integer",
                "description": "Maximum number of techniques to return.",
                "default": 3,
            },
        },
        "required": ["text"],
    },
}

SUBMIT_INCIDENT_REPORT_TOOL = {
    "name": "submit_incident_report",
    "description": (
        "Submit the final structured incident report. This ends the "
        "investigation — call it exactly once, only after you have gathered "
        "enough evidence via the other tools to justify your conclusions."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "severity": {
                "type": "string",
                "enum": ["low", "medium", "high", "critical"],
                "description": "Overall incident severity.",
            },
            "summary": {
                "type": "string",
                "description": "2-4 sentence plain-language summary of what happened.",
            },
            "key_indicators": {
                "type": "array",
                "items": {"type": "string"},
                "description": "The specific IOCs (values) most relevant to this incident.",
            },
            "attack_techniques": {
                "type": "array",
                "items": {"type": "string"},
                "description": "MITRE ATT&CK technique IDs (e.g. 'T1110') implicated in this incident.",
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Concrete, prioritized next steps for the on-call analyst.",
            },
        },
        "required": ["severity", "summary", "key_indicators", "attack_techniques", "recommended_actions"],
    },
}

INVESTIGATION_TOOLS = [
    EXTRACT_IOCS_TOOL,
    ENRICH_INDICATORS_TOOL,
    ANALYZE_AUTH_LOG_TOOL,
    MAP_ATTACK_TECHNIQUES_TOOL,
]

ALL_TOOLS = INVESTIGATION_TOOLS + [SUBMIT_INCIDENT_REPORT_TOOL]
