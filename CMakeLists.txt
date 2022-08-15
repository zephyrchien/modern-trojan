cmake_minimum_required(VERSION 3.19)

set(VCPKG "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
set(CMAKE_TOOLCHAIN_FILE ${VCPKG})

project(trojan)


set(CMAKE_CXX_STANDARD 20)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

file(GLOB_RECURSE CXX_SRC "src/*.cpp")
add_executable(trojan ${CXX_SRC})

option(UDP "Enable UDP Support" ON)
option(STATIC_STD "Static Standard Library" ON) 
option(STATIC_BIN "Static link" OFF)

if(UDP)
    add_definitions(-DTROJAN_USE_UDP)
endif()

if(STATIC_STD)
    target_link_options(trojan PRIVATE -static-libgcc -static-libstdc++)
endif()

if(STATIC_BIN)
    set(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

find_package(asio CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(range-v3 CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

target_include_directories(trojan PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(trojan PRIVATE ${ASIO_INCLUDE_DIR})
target_include_directories(trojan PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(trojan PRIVATE asio::asio)
target_link_libraries(trojan PRIVATE fmt::fmt-header-only)
target_link_libraries(trojan PRIVATE range-v3 range-v3-meta range-v3::meta range-v3-concepts)
target_link_libraries(trojan PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(trojan PRIVATE Threads::Threads)
