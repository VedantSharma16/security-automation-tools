"""Detection rules. Each rule: id, category, severity weight, regex, OWASP LLM mapping."""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: int  # 1-10
    pattern: re.Pattern
    description: str


def _r(id, cat, weight, rx, desc):
    return Rule(id, cat, weight, re.compile(rx, re.I | re.S), desc)


RULES = [
    _r("PI-001", "instruction-override", 9,
       r"\b(ignore|disregard|forget|override|bypass)\b.{0,30}\b(previous|prior|above|earlier|all|any|your|the)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?|directions?|constraints?)\b",
       "Attempts to cancel earlier instructions"),
    _r("PI-002", "prompt-exfiltration", 9,
       r"\b(reveal|print|show|repeat|output|leak|display|tell me|what (is|are))\b.{0,40}\b(system prompt|initial prompt|hidden (instructions|prompt)|your (instructions|rules|prompt)|secret|api[ _-]?key|canary)\b",
       "Attempts to extract the system prompt or secrets"),
    _r("PI-003", "role-hijack", 7,
       r"\b(you are now|from now on you are|act as|pretend (to be|you are)|roleplay as|new persona)\b.{0,60}\b(dan|unrestricted|jailbroken|no (rules|restrictions|filters)|developer mode|evil|root|admin)\b",
       "Persona/jailbreak role reassignment"),
    _r("PI-004", "role-hijack", 6,
       r"\b(developer mode|dan mode|do anything now|god mode|sudo mode)\b",
       "Known jailbreak mode keywords"),
    _r("PI-005", "fake-delimiter", 8,
       r"(\[/?(system|inst|assistant)\]|<\|?(im_start|im_end|system|endoftext)\|?>|^\s*(system|assistant)\s*:|###\s*(system|instruction)s?\b|</?system>)",
       "Spoofed chat-template or role delimiters"),
    _r("PI-006", "data-exfiltration", 9,
       r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&=][^)]*\)|<img[^>]+src=[\"']?https?://[^>]*[?&][^>]*>",
       "Markdown/HTML image beacon that can exfiltrate data via URL query"),
    _r("PI-007", "data-exfiltration", 8,
       r"\b(send|post|forward|email|upload|exfiltrate|transmit)\b.{0,50}\b(conversation|chat history|context|data|credentials|passwords?|secrets?|files?)\b.{0,40}\b(to|at)\b.{0,30}(https?://|@|\bwebhook\b)",
       "Instruction to send data to an external endpoint"),
    _r("PI-008", "tool-abuse", 8,
       r"\b(call|invoke|run|execute|use)\b.{0,25}\b(tool|function|command|shell|terminal|bash|curl|wget|rm -rf|powershell)\b.{0,60}(without|silently|secretly|don'?t (tell|ask|mention)|no (confirmation|approval))",
       "Covert tool invocation request"),
    _r("PI-009", "indirect-injection", 8,
       r"\b(when|if)\b.{0,30}\b(an? )?(ai|assistant|llm|model|chatbot|language model)\b.{0,40}\b(read|reads|process|summari[sz]e|see|sees)\b.{0,60}\b(you must|you should|instead|please)\b|\b(note|message|instruction)s? (to|for) (the )?(ai|assistant|llm|model)\b",
       "Content addressed to the AI embedded in untrusted data"),
    _r("PI-010", "concealment", 5,
       r"\b(do not|don'?t|never)\b.{0,20}\b(tell|inform|mention|reveal|alert|notify)\b.{0,30}\b(the )?(user|human|operator|anyone)\b",
       "Asks the model to hide behaviour from the user"),
    _r("PI-011", "output-hijack", 6,
       r"\b(respond|reply|answer|output)\b.{0,20}\b(only|exactly|solely)\b.{0,20}\b(with|in)\b|\bend (your )?(response|answer) with\b",
       "Forces a specific output format/content"),
]
