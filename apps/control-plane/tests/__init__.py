"""Test package.

Present so ``tests.factories`` has exactly one module name. Without it, running
``mypy .`` sees the same file as both ``factories`` and ``tests.factories`` and
aborts before type-checking anything at all.
"""
