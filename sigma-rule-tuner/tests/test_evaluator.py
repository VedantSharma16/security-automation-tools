from sigma_tuner.evaluator import evaluate_metrics, load_events


def test_load_events_parses_jsonl(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text('{"a": 1}\n\n{"a": 2}\n')  # blank lines must be skipped

    events = load_events(path)

    assert events == [{"a": 1}, {"a": 2}]


def test_evaluate_metrics_counts_confusion_matrix():
    rule = {"detection": {"selection": {"flag": True}, "condition": "selection"}}
    events = [
        {"flag": True, "label": True},  # TP
        {"flag": True, "label": False},  # FP
        {"flag": False, "label": True},  # FN
        {"flag": False, "label": False},  # TN
    ]

    metrics = evaluate_metrics(rule, events)

    assert metrics["tp"] == 1
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tn"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["matched_indices"] == [0, 1]


def test_evaluate_metrics_handles_no_predicted_positives():
    rule = {"detection": {"selection": {"flag": True}, "condition": "selection"}}
    events = [{"flag": False, "label": True}, {"flag": False, "label": False}]

    metrics = evaluate_metrics(rule, events)

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1"] == 0.0


def test_evaluate_metrics_perfect_score():
    rule = {"detection": {"selection": {"flag": True}, "condition": "selection"}}
    events = [{"flag": True, "label": True}, {"flag": False, "label": False}]

    metrics = evaluate_metrics(rule, events)

    assert (metrics["precision"], metrics["recall"], metrics["f1"]) == (1.0, 1.0, 1.0)


def test_missing_label_defaults_to_benign():
    rule = {"detection": {"selection": {"flag": True}, "condition": "selection"}}
    events = [{"flag": True}]  # no "label" key at all

    metrics = evaluate_metrics(rule, events)

    assert metrics["fp"] == 1
    assert metrics["tp"] == 0
