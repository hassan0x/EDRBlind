@echo off
call "C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

:: ── Offset resolver (shared by both variants) ────────────────────────────────
cl Offset_Resolver.c /O2 /GS- /sdl- /link psapi.lib

:: ── RTCore64 suite ──────────────────────────────────────────────────────────
cl EDRBlind.c  /O2 /GS- /sdl- /link psapi.lib

:: ── EVGA EleetX1 suite ───────────────────────────────────────────────────────
cl EDRBlind3.c /O2 /GS- /sdl- /link psapi.lib

:: ── PSKD64 (APSoft PCIScope) suite ──────────────────────────────────────────
cl EDRBlind4.c    /O2 /GS- /sdl- /link psapi.lib
cl pskd64_probe.c  /O2 /GS- /sdl- /link psapi.lib
cl pskd64_probe2.c /O2 /GS- /sdl- /link psapi.lib
cl pskd64_probe3.c /O2 /GS- /sdl- /link psapi.lib

:: ── RTCore64 patched driver ───────────────────────────────────────────────────
echo.
echo [*] Loading RTCore64 (patched) driver...
sc stop   RTCore64 >nul 2>&1
sc delete RTCore64 >nul 2>&1
if not exist "%CD%\drivers\rtcore64_patched.sys" (
    echo [-] rtcore64_patched.sys not found in %CD%\drivers\
    goto :eof
)
sc create RTCore64 type= kernel binpath= "%CD%\drivers\rtcore64_patched.sys" >nul
sc start  RTCore64 >nul 2>&1
sc query  RTCore64 | findstr STATE
if errorlevel 1 (
    echo [-] RTCore64 failed to start
) else (
    echo [+] RTCore64 loaded
)
goto :eof
