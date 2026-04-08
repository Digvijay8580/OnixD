import os
import re

file_path = "onixscanner.py"
with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
    code = f.read()

# Fix bare exceptions safely
code = re.sub(r'except:', 'except Exception:', code)
code = re.sub(r'except\s*:', 'except Exception:', code)

# Renames
code = code.replace("runTest", "run_test")
code = code.replace("bcolors", "BColors")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(code)
