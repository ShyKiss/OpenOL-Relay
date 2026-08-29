@echo off
:: Build OpenOL_Relay on Windows (MSVC or MinGW via cmake+ninja).
:: Usage:
::   build_win.bat [Release|Debug] [--gui]
::
:: Output:
::   dist\OpenOL_Relay.exe        - CLI
::   dist\OpenOL_Relay_GUI\       - GUI + SDL2.dll
::
:: Requirements:
::   cmake + ninja in PATH
::   GUI: SDL2 installed (set SDL2_DIR or place in MSYS2 default paths)

setlocal enabledelayedexpansion

set BUILD_TYPE=Release
set BUILD_GUI=OFF

for %%A in (%*) do (
    if /I "%%A"=="--gui"   set BUILD_GUI=ON
    if /I "%%A"=="Debug"   set BUILD_TYPE=Debug
    if /I "%%A"=="Release" set BUILD_TYPE=Release
)

if not exist dist mkdir dist

:: --- CLI ---
if exist build_win\cmake_cli\CMakeCache.txt del /F /Q build_win\cmake_cli\CMakeCache.txt

cmake -S . -B build_win\cmake_cli -G Ninja ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DBUILD_GUI=OFF
if %ERRORLEVEL% neq 0 ( echo CMake CLI configure failed. & exit /b %ERRORLEVEL% )

cmake --build build_win\cmake_cli
if %ERRORLEVEL% neq 0 ( echo CLI build failed. & exit /b %ERRORLEVEL% )

copy /Y build_win\cmake_cli\OpenOL_Relay.exe dist\OpenOL_Relay.exe
echo Built: dist\OpenOL_Relay.exe  (%BUILD_TYPE%)

if "%BUILD_GUI%"=="OFF" exit /b 0

:: --- GUI ---
git config --global --add safe.directory *
if exist build_win\cmake_gui\CMakeCache.txt del /F /Q build_win\cmake_gui\CMakeCache.txt

cmake -S . -B build_win\cmake_gui -G Ninja ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DBUILD_GUI=ON
if %ERRORLEVEL% neq 0 ( echo CMake GUI configure failed. & exit /b %ERRORLEVEL% )

cmake --build build_win\cmake_gui
if %ERRORLEVEL% neq 0 ( echo GUI build failed. & exit /b %ERRORLEVEL% )

set OUT_GUI_DIR=dist\OpenOL_Relay_GUI
if not exist %OUT_GUI_DIR% mkdir %OUT_GUI_DIR%
copy /Y build_win\cmake_gui\OpenOL_Relay_GUI.exe %OUT_GUI_DIR%\OpenOL_Relay_GUI.exe

:: Copy SDL2.dll
for %%D in ("%SDL2_DIR%\bin" "%SDL2_DIR%\lib\x64" "C:\msys64\mingw64\bin" "C:\msys64\ucrt64\bin") do (
    if exist "%%~D\SDL2.dll" (
        copy /Y "%%~D\SDL2.dll" "%OUT_GUI_DIR%\SDL2.dll" >nul
        echo Copied SDL2.dll from %%~D
    )
)

echo Built: %OUT_GUI_DIR%\OpenOL_Relay_GUI.exe  (%BUILD_TYPE%)
echo Done.

endlocal
