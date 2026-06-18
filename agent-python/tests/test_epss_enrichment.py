import gzip
from datetime import datetime, timezone

from enrichment.epss import FIRST_EPSS_CSV_URL, load_epss_catalog, parse_epss_api, parse_epss_csv


def test_epss_parser_handles_api_like_sample():
    result = parse_epss_api(
        {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2026-1111",
                    "epss": "0.00561",
                    "percentile": "0.42218",
                    "date": "2026-06-18",
                }
            ],
        }
    )

    entry = result.entries["CVE-2026-1111"]
    assert result.valid_rows == 1
    assert entry.probability == 0.00561
    assert entry.percentile == 0.42218
    assert entry.date == "2026-06-18"
    assert entry.to_enrichment() == {
        "available": True,
        "probability": 0.00561,
        "percentile": 0.42218,
        "date": "2026-06-18",
        "source": "FIRST",
    }


def test_epss_parser_handles_bulk_csv_score_date_and_missing_records():
    result = parse_epss_csv(
        "\n".join(
            [
                "#model_version:v2026.06.15,score_date:2026-06-18T12:00:27Z",
                "cve,epss,percentile",
                "CVE-2026-1111,0.95,0.99",
                "CVE-2026-2222,0.002,0.20",
            ]
        )
    )

    assert result.source_date == "2026-06-18"
    assert result.valid_rows == 2
    assert result.entries["CVE-2026-1111"].date == "2026-06-18"
    assert "CVE-2026-9999" not in result.entries


def test_epss_parser_rejects_invalid_numbers_instead_of_inventing_values():
    result = parse_epss_csv(
        "\n".join(
            [
                "cve,epss,percentile",
                "CVE-2026-1111,not-a-number,0.99",
                "CVE-2026-2222,1.2,0.99",
            ]
        )
    )

    assert result.valid_rows == 0
    assert result.malformed_rows == 2


def test_epss_catalog_refresh_decompresses_and_caches(tmp_path):
    text = "\n".join(
        [
            "#model_version:v2026.06.15,score_date:2026-06-18T12:00:27Z",
            "cve,epss,percentile",
            "CVE-2026-1111,0.95,0.99",
        ]
    )
    calls = []

    def fetcher(url, timeout):
        calls.append((url, timeout))
        return gzip.compress(text.encode("utf-8"))

    catalog = load_epss_catalog(
        cache_dir=tmp_path,
        refresh=True,
        fetcher=fetcher,
        now=lambda: datetime(2026, 6, 18, tzinfo=timezone.utc),
    )
    cached = load_epss_catalog(cache_dir=tmp_path, offline=True, fetcher=lambda *_args: (_ for _ in ()).throw(AssertionError("network used")))

    assert calls == [(FIRST_EPSS_CSV_URL, 30.0)]
    assert catalog.available is True
    assert cached.cache_hit is True
    assert cached.lookup("CVE-2026-1111")["probability"] == 0.95
    assert cached.lookup("CVE-2026-9999") == {"available": False, "source": "FIRST", "date": "2026-06-18"}


def test_epss_catalog_offline_missing_cache_is_unavailable(tmp_path):
    catalog = load_epss_catalog(cache_dir=tmp_path, offline=True)

    assert catalog.available is False
    assert catalog.lookup("CVE-2026-1111") == {"available": False, "source": "FIRST"}
