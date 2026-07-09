import numpy as np
from scipy import signal as scipy_signal


class SignalTools:
    @staticmethod
    def ou_noise(signal, theta=1.0, mu=0.0, sigma=0.1, dt=0.01):
        n = len(signal)
        noise = np.zeros(n)
        x = 0.0
        for i in range(n):
            dx = theta * (mu - x) * dt + sigma * np.sqrt(dt) * np.random.randn()
            x = x + dx
            noise[i] = x + signal[i] if i < len(signal) else x
        return noise

    @staticmethod
    def langevin_filter(data, k=1.0, dt=0.01):
        filtered = np.zeros_like(data)
        x = 0.0
        for i in range(len(data)):
            dx = -k * x * dt + data[i] * dt
            x = x + dx
            filtered[i] = x
        return filtered

    @staticmethod
    def maxent_mi(x, y, bins=10):
        joint, _, _ = np.histogram2d(x, y, bins=bins)
        joint = joint / joint.sum()
        px = joint.sum(axis=1)
        py = joint.sum(axis=0)
        px_py = np.outer(px, py)
        mask = joint > 0
        mi = np.sum(joint[mask] * np.log(joint[mask] / px_py[mask]))
        return mi

    @staticmethod
    def window_integration(data, window_size=64):
        n = len(data)
        result = np.zeros(n)
        half = window_size // 2
        for i in range(n):
            start = max(0, i - half)
            end = min(n, i + half + 1)
            result[i] = np.trapz(data[start:end])
        return result

    @staticmethod
    def spectral_analysis(data, fs=1.0):
        freqs, psd = scipy_signal.welch(data, fs=fs)
        peaks = scipy_signal.find_peaks(psd)[0]
        peak_freqs = freqs[peaks] if len(peaks) else np.array([])
        peak_mags = psd[peaks] if len(peaks) else np.array([])
        return {"frequencies": freqs, "psd": psd, "peak_frequencies": peak_freqs, "peak_magnitudes": peak_mags}

    @staticmethod
    def higher_order_maxent(data, max_order=3, bins=10):
        if data.ndim == 1:
            data = data.reshape(-1, 1)
        n_dims = data.shape[1]
        results = {}
        for order in range(1, max_order + 1):
            mi_sum = 0.0
            count = 0
            for i in range(n_dims):
                for j in range(i + 1, order + 1):
                    if j < n_dims:
                        mi_sum += SignalTools.maxent_mi(data[:, i], data[:, j], bins=bins)
                        count += 1
            results[order] = mi_sum / count if count else 0.0
        return results

    @staticmethod
    def cross_domain_correlation(domain_a, domain_b):
        a_flat = np.asarray(domain_a).flatten()
        b_flat = np.asarray(domain_b).flatten()
        min_len = min(len(a_flat), len(b_flat))
        if min_len == 0:
            return 0.0
        corr = np.corrcoef(a_flat[:min_len], b_flat[:min_len])
        return float(corr[0, 1]) if corr.shape == (2, 2) else 0.0

    @staticmethod
    def mutual_information_2d(x, y, bins=10):
        return SignalTools.maxent_mi(x, y, bins=bins)
