from noctua.modules.base import AnalyzerModule

class ProfilerModule(AnalyzerModule):
    name = "profiler"
    description = "Instruction type profiler"
    applies_to = []

    def analyze(self):
        try:
            bt = getattr(self.engine, 'binary_type', '')
            if bt == 'dex' and hasattr(self.engine, 'dex_parser'):
                dp = self.engine.dex_parser
                methods = getattr(dp, 'methods', []) or []
                self.results = {'insn_count': len(methods), 'rare_instructions': ['dex_methods']}
            else:
                funcs = getattr(self.engine, 'functions', {})
                insn_count = sum(len(f.instructions) for f in (funcs.values() if isinstance(funcs, dict) else funcs))
                self.results = {'insn_count': insn_count, 'rare_instructions': []}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

