@echo off
REM Optional: download Grype and Trivy (latest releases from GitHub) into tools\ for the benchmark.
setlocal
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first. & exit /b 1)
python -m guardian.get_tools
if exist tools\grype.exe tools\grype.exe version | findstr /B "Version"
if exist tools\trivy.exe tools\trivy.exe --version | findstr /B "Version"
endlocal
