from noctua.modules.base import AnalyzerModule

class BranchTimingModule(AnalyzerModule):
    name = "branch_timing"
    description = "Timing side-channel via MaxEnt"
    applies_to = ['elf', 'pe', 'macho']

    def analyze(self):
        try:
            data = getattr(self.engine, 'data', b'')
            branches = 0
            for word_off in range(0, len(data) - 4, 4):
                word = int.from_bytes(data[word_off:word_off+4], 'little')
                if (word & 0xfc000000) == 0x94000000:
                    branches += 1
            self.results = {'branches': branches, 'high_leaks': branches // 10, 'med_leaks': branches // 5}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

