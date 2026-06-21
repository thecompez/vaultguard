import QtQuick
import QtQuick.Controls.Basic
import VaultGuard

// A captioned, monospaced secret value with a copy affordance.
Column {
    id: root
    property string caption: ""
    property string value: ""
    property bool wrap: false
    signal copied()
    spacing: 6

    Text {
        text: root.caption
        color: Theme.textMuted
        font.family: Theme.fontBody
        font.pixelSize: Theme.sizeSmall
        font.weight: Font.Medium
    }

    Rectangle {
        width: parent.width
        radius: Theme.radiusSm
        color: Theme.bgDeep
        border.width: 1
        border.color: Theme.border
        implicitHeight: Math.max(48, valueText.implicitHeight + Theme.md)

        Text {
            id: valueText
            anchors.verticalCenter: parent.verticalCenter
            x: Theme.md
            width: parent.width - 64
            text: root.value
            color: Theme.text
            font.family: Theme.fontMono
            font.pixelSize: Theme.sizeSmall
            wrapMode: root.wrap ? Text.WrapAnywhere : Text.NoWrap
            elide: root.wrap ? Text.ElideNone : Text.ElideRight
        }

        // Copy button.
        Rectangle {
            anchors.right: parent.right
            anchors.rightMargin: 6
            anchors.verticalCenter: parent.verticalCenter
            width: 40; height: 36; radius: 8
            color: copyHover.hovered ? Theme.surfaceStrong : "transparent"
            Behavior on color { ColorAnimation { duration: Theme.durFast } }
            Canvas {
                anchors.centerIn: parent
                width: 16; height: 16
                onPaint: {
                    var ctx = getContext("2d")
                    ctx.reset()
                    ctx.strokeStyle = Qt.rgba(Theme.textMuted.r, Theme.textMuted.g, Theme.textMuted.b, 1)
                    ctx.lineWidth = 1.4
                    ctx.strokeRect(5, 5, 9, 9)
                    ctx.strokeRect(2, 2, 9, 9)
                }
            }
            HoverHandler { id: copyHover; cursorShape: Qt.PointingHandCursor }
            TapHandler {
                onTapped: {
                    edit.text = root.value
                    edit.selectAll()
                    edit.copy()
                    root.copied()
                }
            }
        }
        // Hidden helper to access the clipboard via copy().
        TextEdit { id: edit; visible: false }
    }
}
