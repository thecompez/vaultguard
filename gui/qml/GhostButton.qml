import QtQuick
import QtQuick.Controls.Basic
import VaultGuard

// Subordinate / secondary action: outlined glass, no fill weight.
Button {
    id: control
    property color tone: Theme.text
    property bool danger: false
    property string iconName: ""
    readonly property color fg: control.danger ? Theme.danger : control.tone
    implicitHeight: 46
    implicitWidth: Math.max(120, contentItem.implicitWidth + 44)
    font.family: Theme.fontBody
    font.pixelSize: Theme.sizeBody
    font.weight: Font.Medium
    hoverEnabled: true

    contentItem: Row {
        spacing: Theme.sm
        opacity: control.enabled ? 1.0 : 0.5
        Icon {
            visible: control.iconName.length > 0
            name: control.iconName
            size: 17
            color: control.fg
            anchors.verticalCenter: parent.verticalCenter
        }
        Text {
            text: control.text
            color: control.fg
            font: control.font
            anchors.verticalCenter: parent.verticalCenter
        }
    }

    background: Rectangle {
        radius: Theme.radiusSm
        color: control.down ? Theme.surfaceStrong
                            : (control.hovered ? Theme.surface : "transparent")
        border.width: 1
        border.color: control.danger
                      ? Qt.rgba(Theme.danger.r, Theme.danger.g, Theme.danger.b, 0.5)
                      : (control.hovered ? Theme.borderStrong : Theme.border)
        Behavior on color { ColorAnimation { duration: Theme.durFast } }
        Behavior on border.color { ColorAnimation { duration: Theme.durFast } }
    }

    HoverHandler { cursorShape: Qt.PointingHandCursor }
}
