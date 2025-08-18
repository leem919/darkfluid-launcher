# darkfluid-launcher
Launcher for Helldivers 2 to connect to [darkfluid-api](https://github.com/leem919/darkfluid-api)

# Usage
Place darkfluidlauncher.exe and darkfluidconfig.json in the same directory and run the exe.
A console output should appear.

# Building
1. Install Python 3 from [python.org](https://python.org)
2. Install the dependencies with `pip install pyinstaller psutil frida-tools==13.7.1`
3. Run `pyinstaller --onefile --clean --icon=darkfluid.ico darkfluidlauncher.py`