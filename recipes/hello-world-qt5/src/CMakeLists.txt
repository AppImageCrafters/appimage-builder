cmake_minimum_required(VERSION 3.14)

project(hello_world_qt5 LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt5 COMPONENTS Core Quick REQUIRED)

add_executable(hello_world_qt5 main.cpp qml.qrc)


target_link_libraries(hello_world_qt5  PRIVATE Qt5::Core Qt5::Quick)


install(TARGETS hello_world_qt5 DESTINATION bin)
