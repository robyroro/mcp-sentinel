from sentinel_core.audit import AuditChain, AuditEvent, SigningKey, canonical_json


def test_hash_chain_detects_tampering():
    chain = AuditChain()
    chain.append(
        "session.started",
        "gateway",
        {"session": "synthetic"},
        timestamp="2026-01-01T00:00:00+00:00",
    )
    chain.append(
        "policy.denied",
        "gateway",
        {"tool": "terminal.execute"},
        timestamp="2026-01-01T00:00:01+00:00",
    )
    assert chain.verify()[0]
    row = chain.events[1]
    chain.events[1] = AuditEvent(
        row.sequence,
        row.timestamp,
        row.event_type,
        row.actor,
        {"tool": "tampered"},
        row.previous_hash,
        row.event_hash,
    )
    valid, message = chain.verify()
    assert not valid
    assert "hash mismatch" in message


def test_ed25519_manifest_signature():
    key = SigningKey.generate()
    payload = canonical_json({"files": {"events.jsonl": "abc"}})
    signature = key.sign(payload)
    assert SigningKey.verify(key.public_pem(), payload, signature)
    assert not SigningKey.verify(key.public_pem(), canonical_json({"files": {}}), signature)
