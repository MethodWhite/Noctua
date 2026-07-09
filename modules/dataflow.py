from noctua.modules.base import AnalyzerModule


class DataflowModule(AnalyzerModule):
    name = "dataflow"
    description = "Sensitive string/data flow analysis"
    applies_to = []

    SENSITIVE_KEYWORDS = [
        "password", "secret", "key", "token", "auth", "credential",
        "cipher", "encrypt", "decrypt", "private", "pwd", "salt",
        "signature", "certificate", "jwt", "session", "cookie",
        "api_key", "apikey", "api_secret", "access_key", "secret_key",
        "sticker", "exif", "first_party", "sticker_maker", "0x5741", "premium",
    ]

    def analyze(self):
        try:
            findings = []
            strings = getattr(self.engine, "strings", {})
            for s in (list(strings.values()) if isinstance(strings, dict) else strings):
                if not isinstance(s, str) or len(s) < 2:
                    continue
                lower = s.lower()
                for kw in self.SENSITIVE_KEYWORDS:
                    if kw in lower:
                        findings.append({"string": s[:80], "matched_keyword": kw})
                        break

            riff_chunks = getattr(self.engine, "riff_chunks", {})
            if isinstance(riff_chunks, dict):
                for name, chunk in riff_chunks.items():
                    for kw in self.SENSITIVE_KEYWORDS:
                        if kw in name or (isinstance(chunk, bytes) and kw.encode() in chunk):
                            findings.append({"string": f"<{name}>", "matched_keyword": kw})

            self.results = {
                "total_refs": len(findings),
                "samples": [f["string"] for f in findings[:5]],
            }
        except Exception as e:
            self.results = {"error": f"dataflow analysis failed: {e}"}
        return self.results
