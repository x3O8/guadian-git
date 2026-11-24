@echo off
REM Day 1 scan + Day 2 analysis of Juice Shop, tests, then the dashboard.
setlocal
cd /d "%~dp0"
call .venv\Scripts\activate.bat || (echo Run setup.bat first. & exit /b 1)
set PYTHONUTF8=1

if exist target\juice-shop-scenario rmdir /s /q target\juice-shop-scenario
if exist reports\scenario rmdir /s /q reports\scenario

echo ==^> Day 1: scan OWASP Juice Shop (agents 1-5)
python -m guardian.cli --repo target\juice-shop --out reports

echo.
echo ==^> Day 2: prioritise, investigate, plan fixes (agents 6-7; stops for human approval)
python -m guardian.day2 plan --repo target\juice-shop

echo.
echo ==^> Tests
python -m pytest -q

echo.
echo ==^> Dashboard on http://localhost:8501  (Ctrl+C to stop)
echo     Approve fixes on "8 - Remediation ^& approval", then validate them on "9 - Validation".
streamlit run app.py
endlocal
