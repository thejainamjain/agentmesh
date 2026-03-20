"""
Root conftest.py — adds the project root to sys.path so that
both `agentmesh` and `integrations` are importable in tests.
"""
import sys
from pathlib import Path

# Ensure the repo root is on the path
sys.path.insert(0, str(Path(__file__).parent))