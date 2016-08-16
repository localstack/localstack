import os
import sys

# fix PYTHONPATH
root_path = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
parent_path = os.path.realpath(os.path.join(root_path, ".."))
sys.path = [p for p in sys.path if p != parent_path]
