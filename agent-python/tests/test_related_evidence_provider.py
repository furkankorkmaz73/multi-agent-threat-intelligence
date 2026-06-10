from analysis.evidence import NullRelatedEvidenceProvider, RelatedEvidenceAdapter, coerce_related_evidence_provider


def test_none_related_evidence_provider_returns_empty_results():
    provider = coerce_related_evidence_provider(None)

    assert isinstance(provider, NullRelatedEvidenceProvider)
    assert provider.find_related_urlhaus(["rce"], limit=3) == []
    assert provider.find_related_dread(["rce"], limit=3) == []
    assert provider.find_related_cves(["rce"], limit=3) == []


def test_related_evidence_adapter_preserves_existing_fake_db_methods():
    class PartialFakeDB:
        def __init__(self):
            self.calls = []

        def find_related_dread(self, keywords, limit=20):
            self.calls.append(("dread", keywords, limit))
            return [{"title": "Exploit thread"}]

    db = PartialFakeDB()
    provider = coerce_related_evidence_provider(db)

    assert isinstance(provider, RelatedEvidenceAdapter)
    assert provider.find_related_dread(["vpn"], limit=7) == [{"title": "Exploit thread"}]
    assert provider.find_related_urlhaus(["vpn"], limit=7) == []
    assert provider.find_related_cves(["vpn"], limit=7) == []
    assert db.calls == [("dread", ["vpn"], 7)]
