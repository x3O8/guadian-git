@echo off
REM One-time setup for Windows CMD: venv, Python deps, scanners, Juice Shop, lockfile.
setlocal
cd /d "%~dp0"

where python >nul 2>nul || (echo [x] Python not found. Install Python 3.10+ and tick "Add to PATH". & exit /b 1)
where git    >nul 2>nul || (echo [x] git not found. Install Git for Windows. & exit /b 1)
where npm    >nul 2>nul || (echo [x] npm not found. Install Node.js 22+. & exit /b 1)

echo ==^> 1/5 Python virtual environment + dependencies
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat || exit /b 1
python -m pip install --upgrade pip -q
python -m pip install -r requirements.txt || exit /b 1

echo ==^> 2/5 Scanners into tools\
if not exist tools mkdir tools
if not exist tools\syft.exe (
  curl -L -o tools\syft.zip https://github.com/anchore/syft/releases/download/v1.33.0/syft_1.33.0_windows_amd64.zip || exit /b 1
  tar -xf tools\syft.zip -C tools || exit /b 1
  del tools\syft.zip
)
if not exist tools\osv-scanner.exe (
  curl -L -o tools\osv-scanner.exe https://github.com/google/osv-scanner/releases/download/v2.2.4/osv-scanner_windows_amd64.exe || exit /b 1
)

echo ==^> 3/5 Allow long paths in git (Juice Shop has very long file names)
git config --global core.longpaths true

echo ==^> 4/5 Clone OWASP Juice Shop (official repo)
if not exist target mkdir target
if not exist reports mkdir reports
if not exist target\juice-shop (
  git clone --depth 200 https://github.com/juice-shop/juice-shop.git target\juice-shop || exit /b 1
)

echo ==^> 5/5 Resolve dependency tree into package-lock.json (no install scripts run)
pushd target\juice-shop
call npm install --package-lock-only --ignore-scripts --package-lock=true --no-audit --no-fund
if errorlevel 1 (popd & exit /b 1)
popd

REM remove the old synthetic scenario from earlier versions, if present
if exist target\juice-shop-scenario rmdir /s /q target\juice-shop-scenario
if exist reports\scenario rmdir /s /q reports\scenario

echo.
echo Setup complete. Next: run.bat
endlocal
