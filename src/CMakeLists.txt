cmake_minimum_required(VERSION 3.16)
project(OpenOL_Relay C CXX)

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)

# On Windows with GCC/Clang: link everything statically so no runtime DLLs needed.
if(WIN32 AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_link_options(-static-libgcc -static-libstdc++
                     -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive)
endif()

# ---------------------------------------------------------------------------
# Common server sources (pure C)
# ---------------------------------------------------------------------------

set(SERVER_SOURCES server.c cli.c db.c)

# ---------------------------------------------------------------------------
# CLI target
# ---------------------------------------------------------------------------

add_executable(OpenOL_Relay main.cpp ${SERVER_SOURCES})

target_compile_options(OpenOL_Relay PRIVATE
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:Debug>:-g>
)

if(WIN32)
    target_link_libraries(OpenOL_Relay PRIVATE ws2_32)
endif()

# ---------------------------------------------------------------------------
# GUI target (optional, requires ImGui + OpenGL/D3D)
# ---------------------------------------------------------------------------

option(BUILD_GUI "Build OpenOL_Relay_GUI (requires ImGui)" OFF)

if(BUILD_GUI)
    include(FetchContent)

    FetchContent_Declare(imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.91.9
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(imgui)

    set(IMGUI_COMMON_SOURCES
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    )

    if(WIN32)
        set(IMGUI_BACKEND_SOURCES
            ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
            ${imgui_SOURCE_DIR}/backends/imgui_impl_dx9.cpp
        )
        set(IMGUI_BACKEND_LIBS ws2_32 d3d9 dwmapi imm32)
        set(GUI_WIN32_FLAG WIN32)
    else()
        find_package(OpenGL REQUIRED)
        find_package(SDL2 REQUIRED)
        set(IMGUI_BACKEND_SOURCES
            ${imgui_SOURCE_DIR}/backends/imgui_impl_sdl2.cpp
            ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
        )
        set(IMGUI_BACKEND_LIBS OpenGL::GL SDL2::SDL2)
        set(GUI_WIN32_FLAG "")
    endif()

    add_executable(OpenOL_Relay_GUI ${GUI_WIN32_FLAG}
        main.cpp
        gui_app.cpp
        ${SERVER_SOURCES}
        ${IMGUI_COMMON_SOURCES}
        ${IMGUI_BACKEND_SOURCES}
    )

    target_compile_definitions(OpenOL_Relay_GUI PRIVATE BUILD_GUI
        $<$<BOOL:${WIN32}>:GUI_BACKEND_DX9>
        $<$<NOT:$<BOOL:${WIN32}>>:GUI_BACKEND_SDL_GL>
    )

    target_include_directories(OpenOL_Relay_GUI PRIVATE
        ${imgui_SOURCE_DIR}
        ${imgui_SOURCE_DIR}/backends
        $<$<NOT:$<BOOL:${WIN32}>>:${SDL2_INCLUDE_DIRS}>
    )

    target_compile_options(OpenOL_Relay_GUI PRIVATE
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Debug>:-g>
    )

    target_link_libraries(OpenOL_Relay_GUI PRIVATE ${IMGUI_BACKEND_LIBS})
    if(WIN32)
        target_link_libraries(OpenOL_Relay_GUI PRIVATE ws2_32)
    endif()
endif()
