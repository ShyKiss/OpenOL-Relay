#!/usr/bin/env sh

# This will build and run

cd /opt/games/OpenOL-Relay/src

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

./build/OpenOL_Relay
