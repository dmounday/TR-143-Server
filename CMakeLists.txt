cmake_minimum_required(VERSION 3.18)
# 
# Set Tool chain variables
set(CMAKE_TOOLCHAIN_FILE RPiCrossTools.cmake)

project(TR143_TEST_SERVER VERSION 1.0
        DESCRIPTION "TR143-Server"
  LANGUAGES C)
  
include(CMakePrintHelpers)
include(ExternalProject)
cmake_print_variables(CMAKE_PROJECT_NAME PROJECT_NAME CMAKE_INSTALL_PREFIX
                      CMAKE_SYSTEM_PREFIX_PATH
                      CMAKE_BINARY_DIR)

set(CMAKE_C_STANDARD 99)

add_subdirectory(gslib)

add_executable(TR143_Server httpserver.c)
target_link_libraries(TR143_Server PRIVATE gslib AuxLib)


add_executable(UDPEcho UDPEcho.c)
target_link_libraries(UDPEcho PRIVATE AuxLib gslib)






