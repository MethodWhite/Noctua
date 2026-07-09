from noctua.modules.base import AnalyzerModule

class FingerprintModule(AnalyzerModule):
    name = "fingerprint"
    description = "Compiler/packer/language ID"
    applies_to = []

    def analyze(self):
        try:
            data = getattr(self.engine, 'data', b'')
            hints = []
            sigs = [('GCC', b'GCC:'), ('Clang', b'clang'), ('Rust', b'rustc'), ('Go', b'go1.')]
            for name, sig in sigs:
                if sig in data:
                    hints.append(name)
            sections = getattr(self.engine, 'sections', {})
            sec_names = ' '.join(sections.keys() if isinstance(sections, dict) else [])
            if 'comment' in sec_names.lower(): hints.append('Has_comment')
            if 'debug' in sec_names.lower(): hints.append('Has_debug')
            self.results = {'compiler_hints': hints, 'size': len(data), 'type': getattr(self.engine, 'binary_type', '')}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

