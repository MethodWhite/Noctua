import re, json

class NOCTUAAnalyzer:
    def __init__(self, engine):
        self.engine = engine
        self.findings = []

    def run(self):
        self.findings = []
        if self.engine.type == 'dex':
            self._analyze_dex()
        elif self.engine.type == 'webp':
            self._analyze_webp()
        return self.findings

    def _analyze_dex(self):
        dex = self.engine.parsed
        for cls in dex.get('classes', []):
            name = cls.get('name', '')
            if 'LX/4wQ' in name or 'LX/3DL' in name or 'LX/51Y' in name:
                self.findings.append({
                    'type': 'target_class',
                    'class': name,
                    'details': f'Found target class: {name}',
                })

    def _analyze_webp(self):
        for chunk in self.engine.parsed.get('chunks', []):
            if chunk['id'] == 'EXIF':
                self.findings.append({
                    'type': 'exif_chunk',
                    'size': chunk['size'],
                    'offset': chunk['offset'],
                    'details': f'EXIF chunk found at offset {chunk["offset"]}, size {chunk["size"]}',
                })

    def get_report(self):
        return self.findings
