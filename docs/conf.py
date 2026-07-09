# Sphinx config for Noctua (Python)
# Uso: sphinx-build -b html docs/ docs/_build
# O:   sphinx-apidoc -o docs/ . && sphinx-build -b html docs/ docs/_build

import os
import sys
sys.path.insert(0, os.path.abspath('..'))

project = 'Noctua'
copyright = '2024, MethodWhite'
author = 'MethodWhite'
release = '1.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
]

templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

autodoc_default_options = {
    'members': True,
    'undoc-members': True,
    'show-inheritance': True,
    'special-members': '__init__',
}

napoleon_google_docstring = True
napoleon_numpy_docstring = False
