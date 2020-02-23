import sys, os, hou

path = os.path.join(hou.getenv("PIPELINE"), "python")
sys.path.append(path)