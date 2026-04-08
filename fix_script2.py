import os
import re

file_path = "onixscanner.py"
with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
    code = f.read()

# Add import tempfile
if "import tempfile" not in code:
    code = code.replace("import os\n", "import os\nimport tempfile\n")

# Replace all `/tmp/Onixscan` and `/tmp/onixscan` with tempfile.gettempdir() + '/Onixscan'
# There are permutations like /tmp/rapidscan_temp_aspnet_config_err
# I will use a simple regex replacing '/tmp/' with tempfile.gettempdir() + '/' for all rapidscan and Onixscan strings

code = re.sub(r"'/tmp/([^']+)'", r"os.path.join(tempfile.gettempdir(), '\1')", code)
code = re.sub(r'"/tmp/([^"]+)"', r'os.path.join(tempfile.gettempdir(), "\1")', code)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(code)
