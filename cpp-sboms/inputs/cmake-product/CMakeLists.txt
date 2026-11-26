cmake_minimum_required(VERSION 3.24)
project(sensorhub-gateway VERSION 2.4.0 LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
include(FetchContent)

# Third-party code fetched at configure time (no package manager)
FetchContent_Declare(fmt
  GIT_REPOSITORY https://github.com/fmtlib/fmt.git
  GIT_TAG 8.0.0)
FetchContent_Declare(nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.9.1)
FetchContent_Declare(expat
  GIT_REPOSITORY https://github.com/libexpat/libexpat.git
  GIT_TAG R_2_4_1
  SOURCE_SUBDIR expat)
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(EXPAT_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(EXPAT_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(EXPAT_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(EXPAT_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fmt nlohmann_json expat)

# Vendored copies checked into the repository
add_subdirectory(third_party/zlib EXCLUDE_FROM_ALL)
add_library(cjson STATIC third_party/cjson/cJSON.c)
target_include_directories(cjson PUBLIC third_party/cjson)

add_executable(sensorhub-gateway src/main.cpp)
target_include_directories(sensorhub-gateway PRIVATE third_party/zlib ${CMAKE_BINARY_DIR}/third_party/zlib)
target_link_libraries(sensorhub-gateway PRIVATE fmt::fmt nlohmann_json::nlohmann_json expat zlibstatic cjson)
install(TARGETS sensorhub-gateway RUNTIME DESTINATION bin)
