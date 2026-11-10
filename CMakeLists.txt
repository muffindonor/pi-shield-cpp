cmake_minimum_required(VERSION 3.20)
project(pithing LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_library(pithing_core STATIC
  src/dns/message.cpp
  src/blocklist/domain.cpp
  src/blocklist/domain_set.cpp
  src/blocklist/list_parser.cpp
  src/blocklist/filter.cpp
)
target_include_directories(pithing_core PUBLIC src)
if(MSVC)
  target_compile_options(pithing_core PUBLIC /W4)
else()
  target_compile_options(pithing_core PUBLIC -Wall -Wextra -Wpedantic)
endif()

# MinGW: link the C++ runtime statically. Otherwise the exe loads whichever
# libstdc++-6.dll comes first on PATH, and Git for Windows ships an
# incompatible one (that segfaulted under Git Bash).
if(MINGW)
  add_link_options(-static)
endif()

# Command-line tool: load blocklists, ask "would this domain be blocked?"
add_executable(pithing_check tools/check.cpp)
target_link_libraries(pithing_check PRIVATE pithing_core)

enable_testing()
add_executable(pithing_tests
  tests/test_main.cpp
  tests/test_dns.cpp
  tests/test_domain.cpp
  tests/test_list_parser.cpp
  tests/test_filter.cpp
)
target_link_libraries(pithing_tests PRIVATE pithing_core)
add_test(NAME unit COMMAND pithing_tests)
