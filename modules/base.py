class AnalyzerModule:
    name = ""
    description = ""
    applies_to = []

    def __init__(self, engine):
        self.engine = engine
        self.results = {}

    def analyze(self):
        raise NotImplementedError

    def report(self):
        return self.results
