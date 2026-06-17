from worker.observability import summarize_processing_metrics


def test_summarize_processing_metrics_calculates_throughput_and_latency():
    summary = summarize_processing_metrics(
        processed_count=4,
        failed_count=1,
        elapsed_seconds=2.0,
        latency_ms=[10, 30, 20, 40],
    )

    assert summary["processed"] == 4
    assert summary["failed"] == 1
    assert summary["elapsed_seconds"] == 2.0
    assert summary["docs_per_second"] == 2.0
    assert summary["avg_latency_ms"] == 25.0
    assert summary["p95_latency_ms"] == 40.0


def test_summarize_processing_metrics_handles_empty_and_zero_elapsed_inputs():
    summary = summarize_processing_metrics(
        processed_count=0,
        failed_count=0,
        elapsed_seconds=0,
        latency_ms=[],
    )

    assert summary["docs_per_second"] == 0.0
    assert summary["avg_latency_ms"] == 0.0
    assert summary["p95_latency_ms"] == 0.0
