cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)

set(ADNL_GARLIC_HEADERS
  adnl-garlic-server.hpp
  adnl-garlic-manager.hpp
  adnl-tunnel.h
)
set(ADNL_GARLIC_SOURCE
  adnl-garlic-server.cpp
  adnl-tunnel.cpp
  adnl-garlic-manager.cpp
  adnl-garlic-manager-connection.cpp
  ${ADNL_GARLIC_HEADERS})

add_library(adnl-garlic STATIC ${ADNL_GARLIC_SOURCE})
target_include_directories(adnl-garlic PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/../..
)
target_link_libraries(adnl-garlic PUBLIC adnl overlay)