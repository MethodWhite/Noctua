# Arquitectura

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

## Patrones

| Patrón | Implementación |
|--------|---------------|
| **Strategy** | BinaryLoader (check/load) |
| **Pipeline** | Pipeline con stages registrables |
| **Config Object** | NoctuaConfig dataclass |
| **Result/Monad** | NoctuaResult[T] |
