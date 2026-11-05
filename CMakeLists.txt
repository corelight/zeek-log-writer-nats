cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(Zeek_Log_Writer_NATS)

find_package(Zeek REQUIRED)
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

add_subdirectory(./3rdparty/orbit.c EXCLUDE_FROM_ALL)

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
include(CheckSourceCompiles)
include(CMakePushCheckState)
# The following code tests whether WriterBackend::DoWrites() is available
# so we can define HAVE_WRITER_BACKEND_DO_WRITES_AND_STOPPING for the compiler.
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_FLAGS ${ZEEK_CXX_FLAGS})
set(CMAKE_REQUIRED_INCLUDES ${ZEEK_INCLUDE_DIRS})
# Do not try to link the below.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
check_source_compiles(
    CXX
    [[
    #include <zeek/logging/WriterBackend.h>

    class TestBackend : public zeek::logging::WriterBackend {
        // If DoWrites() does not exist, the compiler will fail on this.
        bool DoWrites(int num_fields, const zeek::threading::Field* const* fields,
                      std::span<zeek::logging::detail::LogRecord> record) override {

            // Stopping() is also only supported via a custom patch
            // https://github.com/zeek/zeek/pull/6023
            if ( Stopping() )
                return false;

            return true;
          }

        bool DoWrite(int num_fields, const zeek::threading::Field* const* fields,
                     zeek::threading::Value** vals) override {
            return false;
        }
    };

]]
    HAVE_WRITER_BACKEND_DO_WRITES_AND_STOPPING)
cmake_pop_check_state()

zeek_plugin_begin(Zeek Log_Writer_NATS)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/Connection.cc)
zeek_plugin_cc(src/NATS.cc)
zeek_plugin_cc(src/NATSCoreWriter.cc)
if (HAVE_WRITER_BACKEND_DO_WRITES_AND_STOPPING)
    zeek_plugin_cc(src/NATSFastPublishWriter.cc)
endif ()

zeek_plugin_link_library(${NATS_LIBRARIES})

zeek_get_plugin_target(plugin_target Zeek Log_Writer_NATS)

zeek_plugin_dist_files(README.md CHANGES COPYING VERSION)
zeek_plugin_end()

target_link_libraries(${plugin_target} PRIVATE jetstream_extra_static)

if (HAVE_WRITER_BACKEND_DO_WRITES_AND_STOPPING)
    target_compile_definitions(${plugin_target}
                               PRIVATE HAVE_WRITER_BACKEND_DO_WRITES_AND_STOPPING=1)
endif ()

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
