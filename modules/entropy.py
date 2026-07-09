from noctua.modules.base import AnalyzerModule

class EntropyModule(AnalyzerModule):
    name = "entropy"
    description = "Shannon entropy per section"
    applies_to = []

    def analyze(self):
        try:
            import numpy as np
            sections = getattr(self.engine, 'sections', {})
            data = getattr(self.engine, 'data', b'')
            high = []
            for name, sec in (list(sections.items()) if isinstance(sections, dict) else enumerate(sections))[:30]:
                if isinstance(sec, dict) and sec.get('size', 0) > 8 and sec.get('offset', 0) > 0:
                    chunk = data[sec['offset']:sec['offset']+min(sec['size'], 65536)]
                    counts = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256)
                    probs = counts / counts.sum()
                    ent = float(-np.sum(probs * np.log2(probs + 1e-12)))
                    if ent > 7.0:
                        high.append(f"{name}: {ent:.2f}")
            self.results = {'high_entropy_sections': high[:10], 'total_high': len(high)}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

