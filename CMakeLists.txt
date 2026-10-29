cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(Zeek_Log_Writer_NATS)

find_package(Zeek CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${Zeek_DIR})

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Try FindLibNATS first (looking for libnats-dev), fall back to cnats
list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(LibNATS QUIET)
if (LibNATS_FOUND)
    message(STATUS "Found libnats via FindLibNATS: ${LIBNATS_LIBRARIES}")
    set(NATS_LIBRARIES ${LIBNATS_LIBRARIES})
    include_directories(BEFORE ${LIBNATS_INCLUDE_DIRS})
else ()
    find_package(cnats CONFIG REQUIRED)
    message(STATUS "Found cnats via CMake config (vcpkg)")
    set(NATS_LIBRARIES cnats::nats)
endif ()

# Build orbit.c from a patched copy in the build directory, keeping the
# submodule clean. Patches already applied to the copy are skipped.
find_program(PATCH_EXECUTABLE patch REQUIRED)
set(ORBIT_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/orbit.c)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/orbit.c
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/3rdparty PATTERN .git EXCLUDE)
file(GLOB ORBIT_PATCHES ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/patches/orbit.c/*.patch)
list(SORT ORBIT_PATCHES)
foreach (patch_file ${ORBIT_PATCHES})
    execute_process(
        COMMAND ${PATCH_EXECUTABLE} -p1 -R -s -f --dry-run -i ${patch_file}
        WORKING_DIRECTORY ${ORBIT_SOURCE_DIR}
        RESULT_VARIABLE patch_applied
        OUTPUT_QUIET ERROR_QUIET)
    if (NOT patch_applied EQUAL 0)
        message(STATUS "Applying ${patch_file}")
        execute_process(COMMAND ${PATCH_EXECUTABLE} -p1 -N -s -i ${patch_file}
                        WORKING_DIRECTORY ${ORBIT_SOURCE_DIR} RESULT_VARIABLE patch_result)
        if (NOT patch_result EQUAL 0)
            message(FATAL_ERROR "Failed to apply ${patch_file}")
        endif ()
    endif ()
endforeach ()

add_subdirectory(${ORBIT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/orbit.c-build EXCLUDE_FROM_ALL)

# Establish version numbers in config.h
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in" "${CMAKE_CURRENT_BINARY_DIR}/config.h"
               @ONLY)

include(ZeekPlugin)

zeek_plugin_begin(Zeek Log_Writer_NATS)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/Connection.cc)
zeek_plugin_cc(src/NATS.cc)
zeek_plugin_cc(src/NATSCoreWriter.cc)
zeek_plugin_cc(src/NATSFastPublishWriter.cc)
zeek_plugin_cc(src/NATSFastThreadWriter.cc)
zeek_plugin_cc(src/FastBatch.cc)
zeek_plugin_link_library(${NATS_LIBRARIES})

zeek_get_plugin_target(plugin_target Zeek Log_Writer_NATS)

zeek_plugin_dist_files(README.md CHANGES COPYING VERSION)
zeek_plugin_end()

target_link_libraries(${plugin_target} PRIVATE jetstream_extra_static)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
