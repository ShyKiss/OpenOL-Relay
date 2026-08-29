#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

BUILD_TYPE="Release"
BUILD_GUI=OFF

for arg in "$@"; do
    case "$arg" in
        --gui)    BUILD_GUI=ON ;;
        Debug)    BUILD_TYPE=Debug ;;
        Release)  BUILD_TYPE=Release ;;
    esac
done

BUILD_DIR="build"

cmake -S . -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DBUILD_GUI="$BUILD_GUI"

cmake --build "$BUILD_DIR"

echo "Built: $BUILD_DIR/OpenOL_Relay  (${BUILD_TYPE})"
if [ "$BUILD_GUI" = "ON" ]; then
    echo "Built: $BUILD_DIR/OpenOL_Relay_GUI  (${BUILD_TYPE})"
fi
