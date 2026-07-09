from noctua.modules.base import AnalyzerModule

class EmbeddedModule(AnalyzerModule):
    name = "embedded"
    description = "Embedded file finder"
    applies_to = []

    def analyze(self):
        try:
            data = getattr(self.engine, 'data', b'')
            files = []
            sigs = [('ZIP', b'PK\x03\x04'), ('ELF', b'\x7fELF'), ('DEX', b'dex\n'), ('PNG', b'\x89PNG'), ('PDF', b'%PDF')]
            for name, sig in sigs:
                pos = data.find(sig, 1)
                if pos > 0:
                    files.append(f"{name} @ 0x{pos:x}")
            self.results = {'embedded': files[:10]}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

