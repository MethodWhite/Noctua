# Contributing to Noctua

## 🌳 Estrategia de Ramas

```
main          ───●────●────●
                   \    /
feat/*            ●──●──●
                      \
fix/*               ●────●
```

| Rama | Uso |
|------|-----|
| `main` | Estable |
| `feat/*` | Nuevas features |
| `fix/*` | Bugs |
| `refactor/*` | Refactorización |
| `docs/*` | Documentación |

## 🔄 Flujo

```bash
git checkout main && git pull
git checkout -b feat/mi-feature
# ... código ...
git add -A && git commit -m "feat: descripción"
git push -u origin feat/mi-feature
# PR → CI → merge
```

## 📝 Commits

```
feat:     nueva funcionalidad
fix:      corrección de bug
refactor: cambio sin nueva funcionalidad
docs:     documentación
test:     tests
ci:       CI/CD
```

## ✅ CI Pipeline

```
Push/PR → [ruff lint] → [test 3.8] → [test 3.9] → [test 3.10] → [test 3.11]
```

## 🧩 Agregar un Módulo

1. `modules/mi_modulo.py` heredando de `AnalyzerModule`
2. `name`, `description`, `applies_to`, `analyze()`
3. Agregar a `MODULES` en `analyzer/universal.py`

## 🧩 Agregar un Loader

1. `loaders/mi_formato.py` heredando de `BinaryLoader`
2. `check()` y `load()` classmethods
3. El engine lo detecta automáticamente vía `MAGIC_MAP`

## 📋 Metodología: Scrumban

Usamos **GitHub Projects** como Jira interno (gratis).

**Tablero:** https://github.com/users/MethodWhite/projects/2

| Columna | Propósito |
|---------|-----------|
| Backlog | Ideas sin priorizar |
| Sprint | Tareas del sprint actual |
| In Progress | En desarrollo (max 2) |
| Review | En PR |
| Done | Mergeado |

## 🔍 Reportar Bugs

Usar [bug template](.github/ISSUE_TEMPLATE/bug_report.md).
