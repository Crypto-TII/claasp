from pathlib import Path
from distutils.dir_util import copy_tree

Path("_readthedocs").mkdir(exist_ok=True)
Path("_readthedocs/html").mkdir(exist_ok=True)

copy_tree("docs/build/html", "_readthedocs/html")
