from noctua.modules.base import AnalyzerModule

class MI2DModule(AnalyzerModule):
    name = "mi_2d"
    description = "2D mutual information matrix"
    applies_to = []

    def analyze(self):
        try:
            import numpy as np
            from noctua.core.signal import SignalTools
            rng = np.random.default_rng(3)
            n, s = 200, 12
            traces = np.column_stack([SignalTools.ou_noise(s, 0.3, 4.0, rng) for _ in range(n)])
            mi_mat = SignalTools.mutual_information_2d(traces.T, bins=8)
            self.results = {'matrix_shape': str(mi_mat.shape), 'max_pair': float(np.max(mi_mat)), 'mean_mi': float(np.mean(mi_mat))}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

