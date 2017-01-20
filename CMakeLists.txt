cmake_minimum_required(VERSION 2.6)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")
set(PLUGINS_DIR "${CMAKE_INSTALL_PREFIX}/${LIB_INSTALL_DIR}/sysrepo/plugins/" CACHE PATH "Sysrepo plugins directory.")

project(sysrepo-plugin-dt-fw)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_C_FLAGS "-std=gnu99")
set(SOURCES
	src/firmware-upgrade.c)

if(CMAKE_BUILD_TYPE MATCHES "test")
  add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
  target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE DEBUG=1)
  install(TARGETS ${CMAKE_PROJECT_NAME}
	  DESTINATION lib/sysrepo/plugins)
else()
  add_library(${CMAKE_PROJECT_NAME} MODULE ${SOURCES})
  install(TARGETS ${CMAKE_PROJECT_NAME} LIBRARY
	  DESTINATION lib/sysrepo/plugins)
endif()

set_target_properties(${CMAKE_PROJECT_NAME} PROPERTIES OUTPUT_NAME ${CMAKE_PROJECT_NAME} PREFIX "")

find_package(SYSREPO REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${SYSREPO_LIBRARIES})
include_directories(${SYSREPO_INCLUDE_DIRS})

find_package(LIBUBOX REQUIRED)
include_directories(${LIBUBOX_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBUBOX_LIBRARIES})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})
target_link_libraries(${CMAKE_PROJECT_NAME} ${CURL_LIBRARIES})

find_package(OpenSSL REQUIRED)
target_link_libraries(${CMAKE_PROJECT_NAME} ${OPENSSL_LIBRARIES})
include_directories(${OPENSSL_INCLUDE_DIR})
