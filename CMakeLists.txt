cmake_minimum_required(VERSION 3.12)
project(disarm)

set (CMAKE_CXX_STANDARD 23)

add_custom_command(
   OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc
   COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/gen/parse.py ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc ${CMAKE_CURRENT_SOURCE_DIR}/gen/desc.txt --feature-desc ${CMAKE_CURRENT_SOURCE_DIR}/gen/feat.txt --encode-in-header
   DEPENDS gen/parse.py gen/desc.txt gen/feat.txt
)

add_library(disarm OBJECT src/classify.cpp src/encode.cpp src/decode.cpp src/format.cpp src/assembler.cpp ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc)
target_include_directories(disarm PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(disarm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(decode-test test/decode-test.cpp)
target_include_directories(decode-test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(decode-test disarm)

add_executable(encode-test test/encode-test.cpp)
target_include_directories(encode-test PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(encode-test disarm)

add_executable(bf test/bf.cpp)
target_include_directories(bf PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(bf disarm)
