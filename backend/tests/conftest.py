"""Pytest configuration for the backend test suite.

Sets required environment variables before any test module is imported,
so that auth.py (which reads JWT_SECRET at module load time) does not
raise a RuntimeError during test collection.
"""
import os

import pytest


def pytest_configure(config):
    """Set required environment variables as early as possible."""
    os.environ.setdefault("JWT_SECRET", "test-secret-do-not-use-in-production")
