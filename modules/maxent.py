from noctua.modules.base import AnalyzerModule

class MaxEntModule(AnalyzerModule):
    name = "maxent"
    description = "Higher-order MaxEnt for non-linear leakage"
    applies_to = []

    def analyze(self):
        try:
            import numpy as np
            from noctua.core.signal import SignalTools
            rng = np.random.default_rng(1)
            n, s = 500, 10
            traces = np.zeros((n, s))
            labels = rng.integers(0, 4, size=n)
            for i in range(n):
                base = SignalTools.ou_noise(s, 0.2, 3.0, rng)
                traces[i] = base + labels[i] * 0.5 * np.exp(-0.5 * ((np.arange(s) - s/2) / 2)**2)
            _, mi_1 = SignalTools.maxent_mi(traces, labels)
            _, mi_h = SignalTools.higher_order_maxent(traces, labels, order=3)
            self.results = {'first_order_mi': float(mi_1), 'higher_order_mi': float(mi_h), 'improvement': float(mi_h - mi_1)}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

