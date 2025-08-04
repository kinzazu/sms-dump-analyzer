import os

def check_os():
    v = os.uname()
    return v.sysname