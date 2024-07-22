from pathlib import Path

"""Importing this variable is more robust with respect to refactorings compared to relative paths everywhere."""
FUNCTIONS_PATH = Path(__file__).resolve().parent
