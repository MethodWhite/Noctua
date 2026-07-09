from noctua.modules.base import AnalyzerModule

class CallGraphModule(AnalyzerModule):
    name = "callgraph"
    description = "Function call graph builder"
    applies_to = ['elf', 'macho']

    def analyze(self):
        try:
            funcs = getattr(self.engine, 'functions', {})
            edges = 0
            for f in (funcs.values() if isinstance(funcs, dict) else funcs):
                for insn in getattr(f, 'instructions', []):
                    if insn.mnemonic in ('bl', 'blr', 'call'):
                        edges += 1
            self.results = {'edge_count': edges}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

