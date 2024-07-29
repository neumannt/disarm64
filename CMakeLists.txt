cmake_minimum_required(VERSION 3.12)
project(disarm)

add_custom_command(
   OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc
   COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/parse.py ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc ${CMAKE_CURRENT_SOURCE_DIR}/desc.txt --feature-desc ${CMAKE_CURRENT_SOURCE_DIR}/feat.txt --encode-in-header
   DEPENDS parse.py desc.txt feat.txt
)

add_library(disarm OBJECT classify.cpp encode.cpp decode.cpp format.cpp ${CMAKE_CURRENT_BINARY_DIR}/disarm64-public.inc ${CMAKE_CURRENT_BINARY_DIR}/disarm64-private.inc)
target_include_directories(disarm PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
