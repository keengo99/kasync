cmake_minimum_required(VERSION 3.10) 

# set the project name 
project(kasync) 
file(GLOB KASYNC_SOURCE_FILES ../src/*.c)
file(GLOB KASYNC_INCLUDE_FILES ../include/*.h)
add_library(kasync STATIC ${KASYNC_SOURCE_FILES} ${KASYNC_INCLUDE_FILES})
#add_definitions(-DKSOCKET_SSL)
target_include_directories(kasync PUBLIC ../include)
#target_sources(kasync  ${KASYNC_SOURCE_FILES})