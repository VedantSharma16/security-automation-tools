# Guardrail layer ablation

| Configuration | Overall ASR | data_exfiltration | direct_injection | excessive_agency | indirect_injection | system_prompt_leak | Benign FP |
|---|---|---|---|---|---|---|---|
| none | 100% | 100% | 100% | 100% | 100% | 100% | 0% |
| only input_filter | 46% | 67% | 14% | 67% | 100% | 20% | 10% |
| only document_filter | 64% | 33% | 100% | 67% | 0% | 80% | 0% |
| only output_filter | 64% | 0% | 100% | 100% | 100% | 0% | 0% |
| only tool_policy | 86% | 100% | 100% | 0% | 100% | 100% | 0% |
| all layers | 4% | 0% | 14% | 0% | 0% | 0% | 10% |
