from noctua.modules.base import AnalyzerModule

class ByteFrequencyModule(AnalyzerModule):
    name = "bytefreq"
    description = "Byte frequency statistics"
    applies_to = []

    def analyze(self):
        try:
            import numpy as np
            data = getattr(self.engine, 'data', b'')
            sections = getattr(self.engine, 'sections', {})
            stats = {}
            if isinstance(sections, dict) and sections:
                for name, sec in list(sections.items())[:10]:
                    if isinstance(sec, dict) and sec.get('size', 0) > 8 and sec.get('offset', 0) > 0:
                        chunk = data[sec['offset']:sec['offset']+min(sec['size'], 4096)]
                        stats[name] = f"size={len(chunk)}"
            else:
                stats['whole'] = f"size={len(data)}"
            self.results = {'sections': stats}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

