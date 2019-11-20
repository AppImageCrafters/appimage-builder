cmake_minimum_required(VERSION 2.8.0)

project(QtQuickControls2Application)

# Find includes in corresponding build directories
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# Find the QtWidgets library
find_package(Qt5Widgets CONFIG REQUIRED)
find_package(Qt5Qml CONFIG REQUIRED)

add_executable(QtQuickControls2Application src/main.cpp src/qml.qrc)
target_link_libraries(QtQuickControls2Application Qt5::Widgets Qt5::Qml)

install(TARGETS QtQuickControls2Application DESTINATION bin COMPONENT binaries)
install(FILES QtQuickControls2Application.desktop DESTINATION share/applications/ COMPONENT desktop)
install(FILES QtQuickControls2Application.png DESTINATION share/icons/hicolor/scalable/apps/ COMPONENT desktop)
