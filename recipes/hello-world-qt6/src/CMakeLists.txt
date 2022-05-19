cmake_minimum_required(VERSION 3.16)

project(hello_world_qt6 VERSION 0.1 LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 6.2 COMPONENTS Quick REQUIRED)

qt_add_executable(hello_world_qt6 main.cpp)

qt_add_qml_module(hello_world_qt6
    URI hello_world_qt6_qml
    VERSION 1.0
    QML_FILES main.qml 
)

target_link_libraries(hello_world_qt6 PRIVATE Qt6::Quick)
install(TARGETS hello_world_qt6 DESTINATION bin)