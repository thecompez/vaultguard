import QtQuick
import QtQuick.Controls.Basic
import VaultGuard

// Labelled input with helper/error text and an animated focus ring.
// Visible label (never placeholder-only), error shown below the field.
// Root is an Item so it exposes a settable implicitWidth — layouts size it by
// width (Layout.fillWidth) and split row space fairly from implicitWidth.
Item {
    id: root
    property alias text: field.text
    property alias placeholder: field.placeholderText
    property alias echoMode: field.echoMode
    property alias inputField: field
    property string label: ""
    property string helper: ""
    property string error: ""
    property bool required: false
    property bool mono: false

    implicitWidth: 240
    implicitHeight: col.implicitHeight

    Column {
        id: col
        anchors { left: parent.left; right: parent.right }
        spacing: 6

        Row {
            spacing: 4
            visible: root.label.length > 0
            Text {
                text: root.label
                color: Theme.textMuted
                font.family: Theme.fontBody
                font.pixelSize: Theme.sizeSmall
                font.weight: Font.Medium
            }
            Text {
                text: "*"; visible: root.required
                color: Theme.gold
                font.pixelSize: Theme.sizeSmall
            }
        }

        TextField {
            id: field
            width: parent.width
            implicitHeight: 46
            color: Theme.text
            font.family: root.mono ? Theme.fontMono : Theme.fontBody
            font.pixelSize: Theme.sizeBody
            placeholderTextColor: Theme.textFaint
            selectionColor: Qt.rgba(Theme.gold.r, Theme.gold.g, Theme.gold.b, 0.35)
            leftPadding: Theme.md
            rightPadding: Theme.md
            selectByMouse: true

            background: Rectangle {
                radius: Theme.radiusSm
                color: Theme.surface
                border.width: field.activeFocus ? 2 : 1
                border.color: root.error.length > 0
                              ? Theme.danger
                              : (field.activeFocus ? Theme.gold : Theme.border)
                Behavior on color { ColorAnimation { duration: Theme.durBase } }
                Behavior on border.color { ColorAnimation { duration: Theme.durFast } }
            }
        }

        Text {
            width: parent.width
            visible: root.error.length > 0 || root.helper.length > 0
            text: root.error.length > 0 ? root.error : root.helper
            color: root.error.length > 0 ? Theme.danger : Theme.textFaint
            font.family: Theme.fontBody
            font.pixelSize: Theme.sizeMicro
            wrapMode: Text.WordWrap
        }
    }
}
