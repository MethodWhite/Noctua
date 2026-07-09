from noctua.modules.base import AnalyzerModule

class StringXformerModule(AnalyzerModule):
    name = "strings"
    description = "Encoded string detector"
    applies_to = []

    def analyze(self):
        try:
            import base64
            strings = getattr(self.engine, 'strings', {})
            if isinstance(strings, dict):
                strings = list(strings.values())
            decoded = []
            for s in strings[:500]:
                if not isinstance(s, str) or len(s) < 4: continue
                try:
                    d = base64.b64decode(s + '==')
                    if 4 < len(d) < 100 and all(32 <= b < 127 for b in d):
                        decoded.append(f"b64: {d[:40].decode('ascii', errors='replace')}")
                        break
                except: pass
            self.results = {'decoded_strings': decoded[:5]}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

