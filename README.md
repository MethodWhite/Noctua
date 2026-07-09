# Noctua 🔍

**Tool-CyberSec-Forensic-Noctua** — Framework de **reverse engineering** y **análisis forense de binarios** en Python.

Noctua detecta y analiza formatos binarios (ELF, PE, Mach-O, DEX, WASM, WebP) aplicando módulos de análisis como criptografía, entropía, flujo de datos, temporización, espectro, huellas digitales y más.

---

## ✨ Características

### Cargadores (Loaders)
| Formato | Soporte |
|---------|---------|
| **ELF** | Executable and Linkable Format (Linux) |
| **PE** | Portable Executable (Windows) |
| **Mach-O** | Mach Object (macOS/iOS) |
| **DEX** | Dalvik Executable (Android) |
| **WASM** | WebAssembly |
| **WebP** | WebP image format (análisis EXIF) |
| **Generic** | Fallback para binarios desconocidos |

### Módulos de Análisis
| Módulo | Descripción |
|--------|-------------|
| `BranchTiming` | Análisis de temporización de branches (side-channel) |
| `Dataflow` | Detección de strings sensibles (passwords, tokens, keys) |
| `Spectral` | Análisis espectral del binario |
| `MaxEnt` | Máxima entropía para detección de ofuscación |
| `CrossDomain` | Correlación cross-domain |
| `MI2D` | Información mutua 2D |
| `Entropy` | Cálculo de entropía por secciones |
| `Profiler` | Perfilado del binario |
| `Crypto` | Escaneo de constantes criptográficas (AES S-box, base64) |
| `ImportExport` | Análisis de importaciones y exportaciones |
| `Fingerprint` | Huella digital del binario |
| `Embedded` | Detección de archivos embebidos |
| `StringXformer` | Detección de strings codificados (base64) |
| `ByteFrequency` | Frecuencia de bytes |
| `CallGraph` | Análisis del grafo de llamadas |

### Arquitectura (Clean Architecture + Patrones)

```
┌─────────────────────────────────────────────────────┐
│                   Interface Layer                    │
│           analyzer.py, pipeline.py, CLI              │
├─────────────────────────────────────────────────────┤
│                   Application Layer                  │
│     Pipeline (Pipeline pattern), Analyzer modules    │
├─────────────────────────────────────────────────────┤
│                    Domain Layer                      │
│   Config (Config Object), Result (Result/Monad),     │
│   MWREEngine, BinaryLoader (Strategy), Module base   │
├─────────────────────────────────────────────────────┤
│                 Infrastructure Layer                 │
│   Loaders (ELF, PE, Mach-O, DEX, WASM, WebP),       │
│   Core engine, Signal tools                          │
└─────────────────────────────────────────────────────┘
```

**Patrones implementados:**
- **Strategy**: `BinaryLoader` define interfaz `check()` / `load()`
- **Pipeline**: `Pipeline` orquesta stages (detect → load → analyze → modules → report)
- **Config Object**: `NoctuaConfig` centraliza configuración
- **Result/Monad**: `NoctuaResult[T]` para manejo consistente de errores
- **Helper**: Funciones compartidas entre loaders

---

## 📦 Instalación

```bash
git clone https://github.com/MethodWhite/Noctua.git
cd Noctua
pip install -r requirements.txt  # si existe
```

### Dependencias
- Python 3.8+
- `capstone` (para desensamblado)

---

## 🚀 Uso

### Análisis básico
```python
from engine import MWREEngine

eng = MWREEngine("binario.elf")
summary = eng.run()
print(summary)
```

### Con Pipeline
```python
from config import NoctuaConfig
from pipeline import Pipeline, stage_load, stage_analyze, stage_report

cfg = NoctuaConfig(verbose=True)
pipe = Pipeline(cfg)

pipe.register("Load binary", stage_load)
pipe.register("Analyze", stage_analyze)
pipe.register("Report", stage_report)

result = pipe.run("binario.elf")
print(result)
```

### Usando el Analyzer
```python
from core.engine import MWREEngine
from analyzer.universal import NOCTUAAnalyzer

eng = MWREEngine("binario.elf")
eng.run()

analyzer = NOCTUAAnalyzer(eng)
results = analyzer.run()

for module, data in results.items():
    print(f"{module}: {data}")
```

---

## 🧩 Agregar un Nuevo Módulo

1. Crear archivo en `modules/` que herede de `AnalyzerModule`
2. Definir `name`, `description`, `applies_to`
3. Implementar `analyze()` que retorna un dict
4. Agregar a `MODULES` en `analyzer/universal.py`

```python
from modules.base import AnalyzerModule

class MiModulo(AnalyzerModule):
    name = "mi_modulo"
    description = "Mi análisis personalizado"
    applies_to = ['elf', 'pe']

    def analyze(self):
        data = getattr(self.engine, 'data', b'')
        # ... análisis ...
        return {'resultado': 42}
```

---

## 🧪 Testing

```bash
python -c "
from core.engine import MWREEngine
eng = MWREEngine('/bin/ls')
print(eng.binary_type)
print(f'Sectores: {len(eng.sections)}')
print(f'Strings: {len(eng.strings)}')
"
```

---

## 📁 Estructura del Proyecto

```
noctua/
├── engine.py              # Motor de análisis principal
├── analyzer.py            # Analyzer básico
├── config.py              # Config Object (NoctuaConfig)
├── result.py              # Result/Monad (NoctuaResult)
├── pipeline.py            # Pipeline pattern
├── core/
│   ├── engine.py          # MWREEngine
│   ├── instruction.py     # MWInstruction, MWFunction
│   └── signal.py          # Signal processing
├── loaders/
│   ├── base.py            # BinaryLoader (Strategy)
│   ├── elf.py, pe.py, macho.py, dex.py,
│   ├── wasm.py, webp.py, generic.py
├── modules/
│   ├── base.py            # AnalyzerModule base
│   ├── branch_timing.py, dataflow.py, spectral.py,
│   │   maxent.py, cross_domain.py, mi_2d.py,
│   │   entropy.py, profiler.py, crypto.py,
│   │   imports.py, fingerprint.py, embedded.py,
│   │   strings.py, bytefreq.py, callgraph.py
├── analyzer/
│   └── universal.py       # NOCTUAAnalyzer (orquesta módulos)
├── attacks/
│   └── simulator.py       # Simulador de ataques (WebP/EXIF)
├── dex_builder.py         # Constructor de DEX
├── dex_parser.py          # Parser de DEX
└── README.md
```

---

## 🔗 Enlaces

- **Noctua-C** (versión C de alto rendimiento): https://github.com/MethodWhite/Noctua-C
- **Reportar bugs**: https://github.com/MethodWhite/Noctua/issues

---

## ⚖️ Licencia

Uso educativo y forense. Responsabilidad del usuario.
