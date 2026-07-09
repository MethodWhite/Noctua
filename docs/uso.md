# Uso

## Análisis básico

```python
from engine import MWREEngine

eng = MWREEngine("malware.exe")
summary = eng.run()
print(summary)
```

## Análisis completo

```python
from core.engine import MWREEngine
from analyzer.universal import NOCTUAAnalyzer

eng = MWREEngine("binario")
eng.run()
analyzer = NOCTUAAnalyzer(eng)
results = analyzer.run()
```

## Pipeline

```python
from pipeline import Pipeline, stage_load, stage_analyze

pipe = Pipeline()
pipe.register("Load", stage_load)
pipe.register("Analyze", stage_analyze)
result = pipe.run("binario.elf")
```
