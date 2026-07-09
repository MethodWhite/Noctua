# Contributing to Noctua / Noctua-C

## 🧠 Filosofía

Este proyecto sigue **Clean Architecture** y **SOLID principles**.
Cada contribución debe mantener o mejorar la separación de capas y la testabilidad.

## 🧩 Cómo Agregar un Módulo

1. Crear `modules/mi_modulo.py` heredando de `AnalyzerModule`
2. Definir `name`, `description`, `applies_to`
3. Implementar `analyze()` que retorna dict
4. Agregar a `MODULES` en `analyzer/universal.py`

## ✅ Convenciones de Código

- PEP 8
- Type hints obligatorios en funciones públicas
- Nombres: `snake_case` para funciones, `PascalCase` para clases
- Errores: usar `NoctuaResult[T]`

## 📝 Commits

Usar commits atómicos con prefijos:
- `feat:` — nueva funcionalidad
- `refactor:` — cambio de código sin cambio funcional
- `fix:` — corrección de bug
- `docs:` — documentación
- `test:` — tests

## 🔄 Pull Request

1. Crear branch desde `main`: `feat/mi-feature`
2. Commits atómicos
3. PR description clara
