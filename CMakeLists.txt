cmake_minimum_required(VERSION 3.12)
project(disarm)

set (CMAKE_CXX_STANDARD 23)

add_custom_command(
   OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc
   COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/parse.py ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc ${CMAKE_CURRENT_SOURCE_DIR}/desc.txt --feature-desc ${CMAKE_CURRENT_SOURCE_DIR}/feat.txt --encode-in-header
   DEPENDS parse.py desc.txt feat.txt
)

add_library(disarm OBJECT classify.cpp encode.cpp decode.cpp format.cpp assembler.cpp ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc)
target_include_directories(disarm PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

add_executable(decode-test test/decode-test.cpp)
target_include_directories(decode-test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(decode-test disarm)

add_executable(encode-test test/encode-test.cpp)
target_include_directories(encode-test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(encode-test disarm)

add_executable(bf test/bf.cpp)
target_include_directories(bf PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(bf disarm)

#add_executable(test test.cpp)
#target_include_directories(test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
#target_link_libraries(test disarm)

