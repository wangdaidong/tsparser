cmake_minimum_required (VERSION 2.6)
project (tsparser)

set(C++11 ON CACHE bool "Build with c++11")
set(OPTIMIZATION OFF CACHE bool "enable optimization")
set(DEBUG ON CACHE bool "Build with debug")
set(WARN ON CACHE bool "enable warn")

if(C++11)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
  add_definitions(-D__cplusplus=201103L)
endif()

if(OPTIMIZATION)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
endif()

if(DEBUG)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g3")
endif()

if(WARN)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
endif()

#oupt put directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

file(GLOB tsparser_src	"${CMAKE_CURRENT_SOURCE_DIR}/src/*")

# add the executable
add_executable (tsparser ${tsparser_src})
