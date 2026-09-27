@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Always resolve paths from this file, regardless of the caller's directory.
if /i "%~1"=="--help" goto help
if /i "%~1"=="help" goto help
if "%~1"=="" goto install
if /i "%~1"=="install" goto install
if /i "%~1"=="backend" goto backend
if /i "%~1"=="frontend" goto frontend
if /i "%~1"=="test" goto test
echo Unknown command: use setup.bat --help
exit /b 2

:install
where uv >nul 2>nul
if errorlevel 1 goto missing_uv
where node >nul 2>nul
if errorlevel 1 goto missing_node
where npm >nul 2>nul
if errorlevel 1 goto missing_node
node -e "const [m,n]=process.versions.node.split('.').map(Number);process.exit((m===20&&n>=19)||(m===22&&n>=12)||m>=24?0:1)"
if errorlevel 1 goto old_node
if not exist "%~dp0.env" if exist "%~dp0.env.example" (
    copy "%~dp0.env.example" "%~dp0.env" >nul
    echo Created .env from .env.example
)
pushd "%~dp0ecdat-backend"
if errorlevel 1 exit /b 1
echo Installing backend Python dependencies with uv...
call uv sync --frozen --extra dev
if errorlevel 1 goto failed
popd
pushd "%~dp0ecdat-web"
if errorlevel 1 exit /b 1
echo Installing frontend Node packages with npm...
call npm ci
if errorlevel 1 goto failed
popd
echo.
echo Local dependencies are installed.
echo Next: edit AUTH_USERNAME and AUTH_PASSWORD in root .env.
echo Then run setup.bat backend and setup.bat frontend in separate terminals.
echo Open http://localhost:5173
exit /b 0

:backend
where uv >nul 2>nul
if errorlevel 1 goto missing_uv
if not exist "%~dp0ecdat-backend\.venv\Scripts\python.exe" goto not_installed
if not defined EVIDENCE_STORE_PATH set "EVIDENCE_STORE_PATH=%~dp0ecdat-backend\evidence_store"
for %%I in ("%EVIDENCE_STORE_PATH%") do set "EVIDENCE_STORE_PATH=%%~fI"
set "ENVIRONMENT=development"
set "ECDAT_DEBUG=false"
set "SESSION_COOKIE_SECURE=false"
set "ALLOWED_HOSTS=["localhost","127.0.0.1"]"
set "CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173","http://localhost:3000","http://127.0.0.1:3000","http://localhost:8000","http://127.0.0.1:8000"]"
pushd "%~dp0ecdat-backend"
if errorlevel 1 exit /b 1
echo Starting local API at http://127.0.0.1:8000
echo Evidence directory: "%EVIDENCE_STORE_PATH%"
echo If port 8000 is occupied by Docker, stop that stack first. Ctrl+C stops this server.
call uv run --frozen --no-sync uvicorn ecdat.apps.api.main:app --host 127.0.0.1 --port 8000 --reload
if errorlevel 1 goto failed
popd
exit /b 0

:frontend
where npm >nul 2>nul
if errorlevel 1 goto missing_node
if not exist "%~dp0ecdat-web\node_modules\.bin\vite.cmd" goto not_installed
pushd "%~dp0ecdat-web"
if errorlevel 1 exit /b 1
echo Starting local UI at http://localhost:5173. Ctrl+C stops this server.
call npm run dev -- --host 127.0.0.1 --port 5173 --strictPort
if errorlevel 1 goto failed
popd
exit /b 0

:test
where uv >nul 2>nul
if errorlevel 1 goto missing_uv
where npm >nul 2>nul
if errorlevel 1 goto missing_node
echo === Running Backend Test Suite ===
pushd "%~dp0ecdat-backend"
call uv run --frozen --no-sync pytest tests -q
set "test_status=%errorlevel%"
popd
if not "%test_status%"=="0" (
    echo Backend tests failed.
    exit /b %test_status%
)
echo.
echo === Running Frontend Linter and Build ===
pushd "%~dp0ecdat-web"
call npm run lint
if errorlevel 1 goto failed
call npm run build
if errorlevel 1 goto failed
popd
echo.
echo === All tests and verification passed! ===
exit /b 0

:failed
set "result=%errorlevel%"
echo Command failed with exit code %result%. Check the output above.
popd
exit /b %result%

:missing_uv
echo uv was not found. Install uv and reopen this terminal, then retry.
echo Installation instructions: https://docs.astral.sh/uv/getting-started/installation/
exit /b 1

:missing_node
echo Node.js and npm are required. Install a supported Node.js LTS and reopen this terminal.
exit /b 1

:old_node
echo Use Node.js 20.19+, 22.12+, or 24+ for this frontend.
exit /b 1

:not_installed
echo Dependencies are missing. Run setup.bat first.
exit /b 1

:help
echo Usage: setup.bat [install ^| backend ^| frontend ^| test ^| --help]
echo   install   Install pinned Python dependencies and npm packages; default action.
echo   backend   Run the local development API on port 8000 in this terminal.
echo   frontend  Run the local development UI on port 5173 in this terminal.
echo   test      Run backend test suite and frontend typecheck/build.
echo.
echo Quickstart:
echo   1. setup.bat
echo   2. Edit root .env: set AUTH_USERNAME and AUTH_PASSWORD (15-128 characters)
echo   3. setup.bat backend   (in Terminal 1)
echo   4. setup.bat frontend  (in Terminal 2)
echo   5. Open http://localhost:5173
exit /b 0
