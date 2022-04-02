#!/usr/bin/python3

import os
import subprocess

print("ONE!")

for k, v in os.environ.items():
    print("%s: %s" % (k, v))

path = os.path.abspath(__file__)
path = os.path.dirname(path)
output = subprocess.check_output([os.path.join(path, "two.py")])
print("exec two from one: " + output.decode())
