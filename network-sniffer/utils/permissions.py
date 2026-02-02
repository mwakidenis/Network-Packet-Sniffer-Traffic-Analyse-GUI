
import sys, os
def check_permissions():
    if sys.platform.startswith("win"): return True
    return os.geteuid() == 0
