cmake_minimum_required(VERSION 3.10) 
project(kfiber_test)
file(GLOB KFIBER_TEST_SOURCE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../kfiber_test/*.c)




add_executable(kfiber_test ${KFIBER_TEST_SOURCE_FILES})
set(KASYNC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
target_include_directories(kfiber_test PUBLIC ${KASYNC_INCLUDE_DIR})

include(CheckSymbolExists)
# Check for macro SEEK_SET
#set(CMAKE_REQUIRED_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}../../include/)
check_symbol_exists(LINUX_IOURING ${KASYNC_INCLUDE_DIR}/kasync_config.h HAVE_LINUX_IOURING)
set(KASYNC_LIBS kasync)
if (HAVE_LINUX_IOURING)
    message(STATUS "found io_uring")
    list(APPEND KASYNC_LIBS uring)
    #target_link_libraries(kfiber_test uring)
endif()
list(APPEND KASYNC_LIBS pthread ssl crypto)
target_link_directories(kfiber_test PUBLIC ../../build)
target_link_libraries(kfiber_test ${KASYNC_LIBS} )