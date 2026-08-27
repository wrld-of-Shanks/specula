"""
Shared path helpers for Specula training/evaluation scripts.

All scripts in this directory may be run from any working directory, so they
must not reference absolute paths on the author's machine. This module resolves
the project root relative to this file and exposes the conventional data and
model directories.

Conventions:
  PROJECT_ROOT  = the repository root (parent of scripts/)
  DATA_DIR      = PROJECT_ROOT/data            (override via $SPECULA_DATA_DIR)
  MODEL_DIR     = PROJECT_ROOT/services/code/models/weights
                                                  (override via $SPECULA_MODEL_DIR)
"""

import os

_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATA_DIR = os.environ.get("SPECULA_DATA_DIR", os.path.join(_project_root, "data"))
MODEL_DIR = os.environ.get(
    "SPECULA_MODEL_DIR",
    os.path.join(_project_root, "services", "code", "models", "weights"),
)


def data_path(*parts):
    """Return an absolute path under the data directory (creating parents)."""
    path = os.path.join(DATA_DIR, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path


def model_path(*parts):
    """Return an absolute path under the model weights directory (creating parents)."""
    path = os.path.join(MODEL_DIR, *parts)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path
