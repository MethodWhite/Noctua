<div align="center">
  <h1>🐍 Noctua</h1>
  <p><strong>Tool-CyberSec-Forensic-Noctua</strong></p>
  <p>Framework de <strong>Reverse Engineering</strong> y análisis forense en Python</p>
  <p>
    <a href="#-características"><img src="https://img.shields.io/badge/7-Formatos_Loader-blue?style=flat-square" alt="Loaders"></a>
    <a href="#-módulos-de-análisis"><img src="https://img.shields.io/badge/15-Módulos-green?style=flat-square" alt="Modules"></a>
    <a href="#-arquitectura"><img src="https://img.shields.io/badge/Clean-Architecture-red?style=flat-square" alt="Architecture"></a>
    <a href="https://github.com/MethodWhite/Noctua/actions"><img src="https://img.shields.io/github/actions/workflow/status/MethodWhite/Noctua/ci.yml?branch=main&style=flat-square&logo=github" alt="CI"></a>
    <a href="#"><img src="https://img.shields.io/badge/Python-3.8+-yellow?style=flat-square" alt="Python"></a>
  </p>
  <p>
    <a href="#-instalación">Instalar</a> •
    <a href="#-uso">Usar</a> •
    <a href="#-arquitectura">Arquitectura</a> •
    <a href="#-agregar-un-módulo">Extender</a>
  </p>
  <br>
</div>

---

**Noctua** es un framework de reverse engineering en **Python** que detecta, analiza y extrae información de binarios. Arquitectura modular con 15 módulos de análisis y clean architecture.

---

## ✨ Características

### Loaders — 7 Formatos

| Formato | Uso | Estado |
|---------|-----|--------|
| **ELF** | Linux, IoT | ✅ |
| **PE** | Windows | ✅ |
| **Mach-O** | macOS/iOS | ✅ |
| **DEX** | Android | ✅ |
| **WASM** | WebAssembly | ✅ |
| **WebP** | Forense de imágenes | ✅ + EXIF |
| **Generic** | Fallback | ✅ |

### Módulos — 15 Análisis

| Módulo | Descripción |
|--------|-------------|
| `BranchTiming` | Side-channel por temporización |
| `Dataflow` | Detección de secrets (passwords, tokens, keys) |
| `Spectral` | Análisis espectral del binario |
| `MaxEnt` | Máxima entropía para ofuscación |
| `CrossDomain` | Correlación cross-domain |
| `MI2D` | Información mutua 2D |
| `Entropy` | Entropía por secciones |
| `Profiler` | Perfilado de secciones |
| `Crypto` | Constantes AES, base64, etc. |
| `ImportExport` | Import/export tables |
| `Fingerprint` | Huella digital del binario |
| `Embedded` | Detección de archivos embebidos |
| `StringXformer` | Strings codificados |
| `ByteFrequency` | Frecuencia de bytes |
| `CallGraph` | Grafo de llamadas |

---

## 🏗️ Arquitectura

```
┌──────────────────────────────────────┐
│  Interface    CLI · analyzer.py      │
├──────────────────────────────────────┤
│  Application  Pipeline · Módulos     │
├──────────────────────────────────────┤
│  Domain       Config · Result        │
├──────────────────────────────────────┤
│  Infra        Loaders · Core Engine  │
└──────────────────────────────────────┘
```

**Patrones:** Strategy · Pipeline · Config Object · Result/Monad

---

## 📦 Instalación

```bash
git clone https://github.com/MethodWhite/Noctua.git
cd Noctua
pip install capstone
```

Requiere Python 3.8+.

---

## 🚀 Uso

```python
from engine import MWREEngine

eng = MWREEngine("malware.exe")
summary = eng.run()
print(summary)
```

```python
from core.engine import MWREEngine
from analyzer.universal import NOCTUAAnalyzer

eng = MWREEngine("binario")
eng.run()
analyzer = NOCTUAAnalyzer(eng)
results = analyzer.run()
```

### Con Pipeline
```python
from pipeline import Pipeline, stage_load, stage_analyze

pipe = Pipeline()
pipe.register("Load", stage_load)
pipe.register("Analyze", stage_analyze)
pipe.run("binario.elf")
```

---

## 🧩 Extender

```python
from modules.base import AnalyzerModule

class MiModulo(AnalyzerModule):
    name = "mi_modulo"
    description = "Análisis personalizado"
    applies_to = ['elf', 'pe']

    def analyze(self):
        data = getattr(self.engine, 'data', b'')
        return {'resultado': 42}
```

[Más en CONTRIBUTING.md](CONTRIBUTING.md)

---

<div align="center">
  <p>Hecho con ❤️ por <a href="https://github.com/MethodWhite">MethodWhite</a></p>
  <p>
    <a href="https://github.com/MethodWhite/Noctua-C">⚡ Noctua-C (C)</a> •
    <a href="https://github.com/MethodWhite/Noctua/issues">🐛 Reportar bug</a>
  </p>
</div>
