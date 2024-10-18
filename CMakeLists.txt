cmake_minimum_required(VERSION 3.10)

project(SecureProgrammingAssignment)

set(CMAKE_CXX_STANDARD 11)

# Specify the path to vcpkg toolchain file
set(CMAKE_TOOLCHAIN_FILE "<path-to-vcpkg>/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# Include directories for vcpkg
include_directories("<path-to-vcpkg>/vcpkg/installed/x64-linux/include")

# Add your source files
add_executable(main server.cpp)
add_executable(client client.cpp)

# Link libraries as needed
# find_package(Boost REQUIRED)
# target_link_libraries(main Boost::Boost)

list(APPEND CMAKE_PREFIX_PATH "/home/devcontainers/secprog/Secure-Programming-Assignment/vcpkg/installed/x64-linux")

find_package(websocketpp REQUIRED)
target_link_libraries(main PRIVATE websocketpp::websocketpp)

find_package(nlohmann_json REQUIRED)
target_link_libraries(main PRIVATE nlohmann_json::nlohmann_json)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(client ${OPENSSL_LIBRARIES})
target_link_libraries(main PRIVATE OpenSSL::SSL)
target_link_libraries(main PRIVATE OpenSSL::Crypto)