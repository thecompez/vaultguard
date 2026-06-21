import QtQuick
import VaultGuard

// Small status / currency chip. Icon-free badge with text + dot.
Rectangle {
    id: root
    property string text: ""
    property color tone: Theme.accent
    property bool dot: true
    implicitWidth: row.implicitWidth + Theme.md
    implicitHeight: 26
    radius: Theme.radiusPill
    color: Qt.rgba(tone.r, tone.g, tone.b, 0.14)
    border.width: 1
    border.color: Qt.rgba(tone.r, tone.g, tone.b, 0.35)

    Row {
        id: row
        anchors.centerIn: parent
        spacing: 6
        Rectangle {
            visible: root.dot
            width: 7; height: 7; radius: 4
            anchors.verticalCenter: parent.verticalCenter
            color: root.tone
        }
        Text {
            text: root.text
            color: root.tone
            font.family: Theme.fontBody
            font.pixelSize: Theme.sizeMicro
            font.weight: Font.DemiBold
            anchors.verticalCenter: parent.verticalCenter
        }
    }
}
