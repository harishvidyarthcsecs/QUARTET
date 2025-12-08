import os
import platform
import zipfile
import subprocess

os_name = platform.system()

if os_name == "Windows":
    zfile = "windows.zip"
    folder = "win_app"
    py = "python"
elif os_name == "Linux":
    zfile = "linux.zip"
    folder = "sih_db"
    py = "python3"
else:
    exit()

if not os.path.isdir(folder):
    with zipfile.ZipFile(zfile, "r") as f:
        f.extractall(".")

subprocess.Popen([py, "app.py"], cwd=folder)

