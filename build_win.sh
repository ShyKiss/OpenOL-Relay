#!/usr/bin/env bash
# Cross-compile OpenOL_Relay for Windows (x86-64) using mingw-w64.
# On Arch: sudo pacman -S mingw-w64-gcc
#
# Usage:
#   ./build_win.sh [Release|Debug] [--gui]
#
# --gui requires Qt6 for Windows (mingw) installed and QT6_MINGW_DIR set:
#   export QT6_MINGW_DIR=/path/to/Qt/6.x.x/mingw_64
set -e

cd "$(dirname "$0")"

CC=x86_64-w64-mingw32-gcc
CXX=x86_64-w64-mingw32-g++

if ! command -v "$CC" &>/dev/null; then
    echo "Error: $CC not found."
    echo "Install with: sudo pacman -S mingw-w64-gcc"
    exit 1
fi

BUILD_TYPE="Release"
BUILD_GUI=OFF

for arg in "$@"; do
    case "$arg" in
        --gui)    BUILD_GUI=ON ;;
        Debug)    BUILD_TYPE=Debug ;;
        Release)  BUILD_TYPE=Release ;;
    esac
done

mkdir -p build_win

FLAGS="-std=c99 -Wall -Wextra -Wpedantic"
CXXFLAGS="-std=c++17 -Wall -Wextra"
if [ "$BUILD_TYPE" = "Debug" ]; then
    FLAGS="$FLAGS -g"
    CXXFLAGS="$CXXFLAGS -g"
else
    FLAGS="$FLAGS -O2"
    CXXFLAGS="$CXXFLAGS -O2"
fi

# --- CLI build (always) ---
OUT_CLI="build_win/OpenOL_Relay.exe"
$CC $FLAGS -o "$OUT_CLI" main.c server.c cli.c db.c -lws2_32
echo "Built: $OUT_CLI  (${BUILD_TYPE})"

# --- GUI build (optional) ---
if [ "$BUILD_GUI" = "ON" ]; then
    if [ -z "$QT6_MINGW_DIR" ]; then
        echo "Error: QT6_MINGW_DIR is not set."
        echo "  export QT6_MINGW_DIR=/usr/x86_64-w64-mingw32"
        exit 1
    fi

    if [ ! -f "$QT6_MINGW_DIR/lib/cmake/Qt6Core/Qt6CoreConfig.cmake" ]; then
        echo "Error: Qt6 for mingw not found at $QT6_MINGW_DIR"
        echo "Install with: yay -S mingw-w64-qt6-base"
        exit 1
    fi

    # Write a minimal CMake toolchain for mingw
    TOOLCHAIN="build_win/mingw_toolchain.cmake"
    cat > "$TOOLCHAIN" <<TCEOF
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_FIND_ROOT_PATH "${QT6_MINGW_DIR}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
TCEOF

    cmake -S . -B build_win/cmake_gui -G Ninja \
        -DCMAKE_TOOLCHAIN_FILE="$(pwd)/$TOOLCHAIN" \
        -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
        -DBUILD_GUI=ON \
        -DCMAKE_PREFIX_PATH="$QT6_MINGW_DIR"

    cmake --build build_win/cmake_gui

    OUT_GUI="build_win/OpenOL_Relay_GUI.exe"
    cp build_win/cmake_gui/OpenOL_Relay_GUI.exe "$OUT_GUI"
    echo "Built: $OUT_GUI  (${BUILD_TYPE})"
    echo ""
    echo "Required DLLs to place next to the .exe (from \$QT6_MINGW_DIR/bin/):"
    echo "  Qt6Core.dll  Qt6Gui.dll  Qt6Widgets.dll"
    echo "  platforms/qwindows.dll  (from \$QT6_MINGW_DIR/plugins/platforms/)"
fi
