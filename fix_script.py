import os
import re

file_path = "onixscanner.py"
with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
    code = f.read()

# Fix 1: Random module -> secrets
code = code.replace("import random", "import secrets as random\nimport shlex", 1)

# Remove the duplicated `import random`
code = code.replace("import random\n", "")

# Fix 2: Command Injection shell=True in Hash Check
old_hash = """cmd = 'sha1sum Onix.py | grep .... | cut -c 1-40'
    oldversion_hash = subprocess.check_output(cmd, shell=True)
    oldversion_hash = oldversion_hash.strip()
    os.system('wget -N https://raw.githubusercontent.com/Digvijay8580/OnixD/refs/heads/main/te.py -O te.py > /dev/null 2>&1')
    newversion_hash = subprocess.check_output(cmd, shell=True)
    newversion_hash = newversion_hash.strip()"""
new_hash = """try:
        oldversion_hash = subprocess.check_output(['sha1sum', 'onixscanner.py']).split()[0].decode().strip()
    except:
        oldversion_hash = ''
    subprocess.call(['wget', '-N', 'https://raw.githubusercontent.com/Digvijay8580/OnixD/refs/heads/main/onixscanner.py', '-O', 'onixscanner.py'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        newversion_hash = subprocess.check_output(['sha1sum', 'onixscanner.py']).split()[0].decode().strip()
    except:
        newversion_hash = ''"""
code = code.replace(old_hash, new_hash)

# Fix 3: Ping
code = code.replace("os.system('ping -c1 github.com > rs_net 2>&1')", "subprocess.call(['ping', '-c1', 'github.com'], stdout=open('rs_net', 'w'), stderr=subprocess.STDOUT)")

# Fix 4: Precheck Injection
old_precheck = """p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)"""
new_precheck = """cmd_list = shlex.split(precmd)
            p = subprocess.Popen(cmd_list, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)"""
code = code.replace(old_precheck, new_precheck)

# Fix 5: Tool Execution Command Injection
old_tool_exec = """        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:"""

new_tool_exec = """        cmd_base = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]
        cmd_list = shlex.split(cmd_base)

        try:
            with open(temp_file, "w") as out:
                subprocess.call(cmd_list, stdout=out, stderr=subprocess.STDOUT)
        except KeyboardInterrupt:"""
code = code.replace(old_tool_exec, new_tool_exec)

# Fix 6: Insecure clear & rm /tmp
code = code.replace("os.system('rm /tmp/Onixscan* > /dev/null 2>&1')", "import glob; [os.remove(f) for f in glob.glob('/tmp/Onixscan*') if os.path.exists(f)]")
code = code.replace("os.system('rm /tmp/Onixscan_te* > /dev/null 2>&1')", "import glob; [os.remove(f) for f in glob.glob('/tmp/Onixscan_te*') if os.path.exists(f)]")
code = code.replace("os.system('clear')", "subprocess.call(['clear'] if os.name == 'posix' else ['cls'])")
code = code.replace("os.system('setterm -cursor off')", "subprocess.call(['setterm', '-cursor', 'off'])")
code = code.replace("os.system('setterm -cursor on')", "subprocess.call(['setterm', '-cursor', 'on'])")
code = code.replace("os.system('rm rs_net > /dev/null 2>&1')", "if os.path.exists('rs_net'): os.remove('rs_net')")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(code)
