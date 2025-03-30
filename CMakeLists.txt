cmake_minimum_required(VERSION 3.16)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)

project(XConfigGen LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找Qt依赖
find_package(Qt6 COMPONENTS Core REQUIRED)

qt_standard_project_setup(REQUIRES 6.5)

set(SRC_FILES src/XConfigGen.cpp)
set(HEADER_FILES src/XConfigGen.h src/models/xray/Xray.h )

# 引入QSerializer库
include(cmake/QSerializer.cmake)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
qt_add_library(${PROJECT_NAME} SHARED ${SRC_FILES} ${HEADER_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# 链接Qt库
target_link_libraries(${PROJECT_NAME} PUBLIC Qt6::Core)
