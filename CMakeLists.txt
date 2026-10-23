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

# Optional fast-ingest support (NATS ADR-50) via orbit.c's jetstream-extra
# library. Requires libnats 3.11 or later.
find_path(ORBIT_INCLUDE_DIR NAMES fast_publish.h HINTS ${ORBIT_ROOT_DIR}/include)
find_library(ORBIT_JETSTREAM_EXTRA_LIBRARY NAMES libjetstream_extra_static.a jetstream_extra
             HINTS ${ORBIT_ROOT_DIR}/lib)
find_library(ORBIT_UTILS_LIBRARY NAMES liborbit_utils_static.a orbit_utils
             HINTS ${ORBIT_ROOT_DIR}/lib)
if (ORBIT_INCLUDE_DIR AND ORBIT_JETSTREAM_EXTRA_LIBRARY AND ORBIT_UTILS_LIBRARY)
    message(STATUS "Found orbit.c fast publish: ${ORBIT_JETSTREAM_EXTRA_LIBRARY}")
    include_directories(BEFORE ${ORBIT_INCLUDE_DIR})
    add_definitions(-DHAVE_ORBIT_FAST_PUBLISH)
    # orbit libraries depend on libnats, so they go first.
    set(NATS_LIBRARIES ${ORBIT_JETSTREAM_EXTRA_LIBRARY} ${ORBIT_UTILS_LIBRARY} ${NATS_LIBRARIES})
else ()
    message(STATUS "orbit.c fast publish not found, PUBLISH_FAST_INGEST unavailable")
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
zeek_plugin_cc(src/Connection.cc)
zeek_plugin_cc(src/NATS.cc)
zeek_plugin_cc(src/NATSCoreWriter.cc)
zeek_plugin_cc(src/FastBatch.cc)
zeek_plugin_link_library(${NATS_LIBRARIES})

zeek_plugin_dist_files(README.md CHANGES COPYING VERSION)
zeek_plugin_end()

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
