def is_malicious(log: str) -> bool:
    signatures = [
        "<script>",
        "' OR 1=1",
        "DROP TABLE",
        "UNION SELECT",
        "1=1",
        "alert(",
        "onerror="
    ]
    return any(sig.lower() in log.lower() for sig in signatures)