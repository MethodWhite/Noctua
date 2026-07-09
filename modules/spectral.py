from noctua.modules.base import AnalyzerModule

class SpectralModule(AnalyzerModule):
    name = "spectral"
    description = "FFT spectral analysis of signals"
    applies_to = []

    def analyze(self):
        try:
            import numpy as np
            from noctua.core.signal import SignalTools
            rng = np.random.default_rng(0)
            sim = np.column_stack([SignalTools.ou_noise(1024, v, 4.0, rng) for v in [0.1, 0.5, 1.0]])
            freqs, spectrum = SignalTools.spectral_analysis(sim.T, fs=1.0)
            peak = float(freqs[np.argmax(spectrum)])
            self.results = {'lorentzian_peak': peak, 'freq_bins': len(freqs)}
        except Exception as e:
            self.results = {'error': str(e)}
        return self.results

