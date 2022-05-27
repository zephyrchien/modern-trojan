cmake_minimum_required(VERSION 3.13)

set(VCPKG "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
set(CMAKE_TOOLCHAIN_FILE ${VCPKG})

project(trojan)

set(CMAKE_CXX_STANDARD 20)
# set(CMAKE_BUILD_TYPE Release)

file(GLOB_RECURSE CXX_SRC "src/*.cpp")
add_executable(trojan ${CXX_SRC})

find_package(asio CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(range-v3 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

target_include_directories(trojan PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(trojan PRIVATE ${ASIO_INCLUDE_DIR})
target_include_directories(trojan PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(trojan PRIVATE asio::asio)
target_link_libraries(trojan PRIVATE fmt::fmt-header-only)
target_link_libraries(trojan PRIVATE range-v3 range-v3-meta range-v3::meta range-v3-concepts)
target_link_libraries(trojan PRIVATE ${OPENSSL_LIBRARIES})
