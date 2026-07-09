from noctua.modules.base import AnalyzerModule
from noctua.modules.branch_timing import BranchTimingModule
from noctua.modules.dataflow import DataflowModule
from noctua.modules.spectral import SpectralModule
from noctua.modules.maxent import MaxEntModule
from noctua.modules.cross_domain import CrossDomainModule
from noctua.modules.mi_2d import MI2DModule
from noctua.modules.entropy import EntropyModule
from noctua.modules.profiler import ProfilerModule
from noctua.modules.crypto import CryptoModule
from noctua.modules.imports import ImportExportModule
from noctua.modules.fingerprint import FingerprintModule
from noctua.modules.embedded import EmbeddedModule
from noctua.modules.strings import StringXformerModule
from noctua.modules.bytefreq import ByteFrequencyModule
from noctua.modules.callgraph import CallGraphModule


class NOCTUAAnalyzer:
    MODULES = [
        BranchTimingModule,
        DataflowModule,
        SpectralModule,
        MaxEntModule,
        CrossDomainModule,
        MI2DModule,
        EntropyModule,
        ProfilerModule,
        CryptoModule,
        ImportExportModule,
        FingerprintModule,
        EmbeddedModule,
        StringXformerModule,
        ByteFrequencyModule,
        CallGraphModule,
    ]

    def __init__(self, engine):
        self.engine = engine
        self.binary_type = getattr(engine, 'binary_type', 'unknown')

    def run(self):
        results = {}
        print(f"=== NOCTUA Universal Analyzer ===")
        print(f"Binary type: {self.binary_type}\n")

        for module_cls in self.MODULES:
            name = module_cls.__name__
            try:
                mod = module_cls(self.engine)
                applies_to = getattr(mod, 'applies_to', [])
                if isinstance(applies_to, list):
                    if applies_to and self.binary_type not in applies_to:
                        print(f"  [SKIP] {name}: not applicable")
                        continue
                elif callable(applies_to):
                    if not applies_to(self.binary_type):
                        print(f"  [SKIP] {name}: not applicable")
                        continue
                data = mod.analyze()
            except Exception as e:
                print(f"  [ERR]  {name}: {e}")
                results[name] = {'error': str(e)}
                continue

            results[name] = data
            self._print_module(name, data)

        return results

    def _print_module(self, name, data):
        print(f"  [{name}]")
        if isinstance(data, dict):
            if name == 'BranchTimingModule':
                print(f"    branches: {data.get('branches', 0)}")
                high = data.get('high_leaks', 0)
                med = data.get('med_leaks', 0)
                print(f"    leaks: {high} HIGH, {med} med")
            elif name == 'DataflowModule':
                print(f"    total refs: {data.get('total_refs', 0)}")
                samples = data.get('samples', [])
                for s in samples[:3]:
                    print(f"      {s}")
            elif name == 'SpectralModule':
                print(f"    Lorentzian peak: {data.get('lorentzian_peak', 'N/A')} Hz")
            elif name == 'MaxEntModule':
                print(f"    1st-order MI: {data.get('first_order_mi', 0):.4f}")
                print(f"    higher-order MI: {data.get('higher_order_mi', 0):.4f}")
            elif name == 'CrossDomainModule':
                print(f"    pairwise correlations: {data.get('pairwise_count', 0)}")
            elif name == 'MI2DModule':
                print(f"    matrix shape: {data.get('matrix_shape', 'N/A')}")
                mp = data.get('max_pair', None)
                if mp:
                    print(f"    max pair: {mp}")
            elif name == 'EntropyModule':
                sections = data.get('high_entropy_sections', [])
                for sec in sections[:5]:
                    print(f"    {sec}")
            elif name == 'ProfilerModule':
                print(f"    instruction count: {data.get('insn_count', 0)}")
                rare = data.get('rare_instructions', [])
                if rare:
                    print(f"    rare instructions: {', '.join(rare[:8])}")
            elif name == 'CryptoModule':
                consts = data.get('constants', [])
                for c in consts[:5]:
                    print(f"    {c}")
            elif name == 'ImportExportModule':
                print(f"    imports: {data.get('imports', 0)}")
                print(f"    exports: {data.get('exports', 0)}")
            elif name == 'FingerprintModule':
                hints = data.get('compiler_hints', [])
                for h in hints[:3]:
                    print(f"    {h}")
            elif name == 'EmbeddedModule':
                files = data.get('embedded', [])
                for f in files[:5]:
                    print(f"    {f}")
            elif name == 'StringXformerModule':
                decoded = data.get('decoded_strings', [])
                for s in decoded[:5]:
                    print(f"    {s}")
            elif name == 'ByteFrequencyModule':
                for sec, stats in data.get('sections', {}).items():
                    print(f"    {sec}: {stats}")
            elif name == 'CallGraphModule':
                print(f"    edges: {data.get('edge_count', 0)}")
            else:
                for k, v in data.items():
                    print(f"    {k}: {v}")
        elif isinstance(data, list):
            for item in data[:5]:
                print(f"    {item}")
        else:
            print(f"    {data}")
        print()
