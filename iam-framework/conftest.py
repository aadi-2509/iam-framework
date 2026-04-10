"""
Shared pytest fixtures for IAM Framework.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "policies"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src", "audit"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "api"))
