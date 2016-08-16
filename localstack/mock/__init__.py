import os
import sys

this_path = os.path.dirname(os.path.realpath(__file__))
root_path = os.path.realpath(os.path.join(this_path, '..', '..'))
if root_path not in sys.path:
    sys.path.insert(0, root_path)
