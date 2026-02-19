cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(Zeek_Log_Writer_NATS)

find_package(Zeek CONFIG REQUIRED)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${Zeek_DIR})
set(BRO_PLUGIN_INSTALL_ROOT ${CMAKE_INSTALL_PREFIX}/lib/zeek/plugins)

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
zeek_plugin_cc(src/NATS.cc)
zeek_plugin_link_library(${NATS_LIBRARIES})

zeek_plugin_dist_files(README.md CHANGES COPYING VERSION)
zeek_plugin_end()

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
