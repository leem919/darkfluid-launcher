# Dark Fluid Launcher
Launcher for Helldivers 2 to connect to [darkfluid-api](https://github.com/leem919/darkfluid-api)

# Usage
Run darkfluidlauncher.exe and darkfluidconfig.json should be created in the same directory.

# Building
1. Install Python 3 from [python.org](https://python.org)
2. Install the dependencies with `pip install -r requirements.txt`
3. Run `pyinstaller --onefile --clean --noconsole --add-data "darkfluid.ico;." --icon=darkfluid.ico darkfluidlauncher.py`