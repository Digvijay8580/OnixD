import os
import re

file_path = "onixscanner.py"
with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
    code = f.read()

# Fix bare exceptions
code = re.sub(r'except:', 'except Exception:', code)
code = re.sub(r'except\s*:', 'except Exception:', code)

# Ensure open() uses explicit encoding where missing
# It's safer to just do a simple replace since kwargs can be anywhere, but regex is fine
code = re.sub(r'''open\(([^,]+?),\s*"w"\)''', r'open(\1, "w", encoding="utf-8")', code)
code = re.sub(r"""open\(([^,]+?),\s*'w'\)""", r"open(\1, 'w', encoding='utf-8')", code)

code = re.sub(r'''open\(([^,]+?),\s*"r"\)''', r'open(\1, "r", encoding="utf-8")', code)
code = re.sub(r"""open\(([^,]+?),\s*'r'\)""", r"open(\1, 'r', encoding='utf-8')", code)

code = re.sub(r'''open\(([^,]+?),\s*"a"\)''', r'open(\1, "a", encoding="utf-8")', code)
code = re.sub(r"""open\(([^,]+?),\s*'a'\)""", r"open(\1, 'a', encoding='utf-8')", code)

# For missing mode entirely e.g. open(file)
code = re.sub(r'open\(([^,)]+?)\)', r'open(\1, encoding="utf-8")', code)
# Also some people do open('rs_net').read()
code = re.sub(r"open\('rs_net'\)\.read\(\)", r"open('rs_net', encoding='utf-8').read()", code)

# Also rename runTest to run_test
code = code.replace("runTest", "run_test")
code = code.replace("bcolors", "BColors")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(code)
