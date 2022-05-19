import QtQuick

Window {
    width: 640
    height: 480
    visible: true
    title: qsTr("Hello World")

    Rectangle {
        anchors.fill: parent

        Text {
            text: "Hello World!"
            anchors.centerIn: parent

        }
    }
}
