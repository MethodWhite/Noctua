from noctua.modules.base import AnalyzerModule

class ImportExportModule(AnalyzerModule):
    name = "imports"
    description = "Import/export symbol extractor"
    applies_to = ['elf', 'pe', 'macho']

    def analyze(self):
        try:
            sections = getattr(self.engine, 'sections', {})
            data = getattr(self.engine, 'data', b'')
            imports = exports = 0
            if isinstance(sections, dict):
                dynsym = sections.get('.dynsym')
                dynstr = sections.get('.dynstr')
                if dynsym and dynstr:
                    imports = dynsym.get('size', 0) // 24 if dynsym.get('size') else 0
            self.results = {'imports': imports, 'exports': exports}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

