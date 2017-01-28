cmake_minimum_required(VERSION 3.5)
project(SpeedTestServer)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic -Wall -Wno-unused-result")
set(SOURCE_FILES main.c protocol.h)
add_executable(SpeedTestServer ${SOURCE_FILES})
FIND_PACKAGE(Libevent2 REQUIRED)


include_directories(${libevent_INCLUDE_DIRS})
target_link_libraries(SpeedTestServer ${libevent_LIBRARIES} -levent)