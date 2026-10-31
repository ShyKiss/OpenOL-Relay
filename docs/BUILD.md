Build from the `src` folder. It needs cmake and ninja:

```sh
cd src
./build.sh         # TUI: build/OpenOL_Relay
./build.sh --gui   # also GUI: build/OpenOL_Relay_GUI
```

On Windows, run `build_win.bat [--gui]` from the same folder. Output: `dist/`.

With plain cmake, `-DBUILD_GUI` toggles whether the GUI will be built or not.

See [the workflows](../.github/workflows) for more details.
