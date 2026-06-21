import QtQuick
import VaultGuard

// Compact segmented control: System · Light · Dark. Writes Theme.mode, which
// re-themes the whole app. A sliding highlight tracks the active segment.
Rectangle {
    id: root
    property bool compact: false
    implicitWidth: row.implicitWidth + 8
    implicitHeight: 34
    radius: Theme.radiusPill
    color: Theme.surface
    border.width: 1
    border.color: Theme.border
    Behavior on color { ColorAnimation { duration: Theme.durBase } }

    // Sliding highlight behind the active segment.
    Rectangle {
        id: pillBg
        height: parent.height - 6
        y: 3
        radius: Theme.radiusPill
        color: Qt.rgba(Theme.gold.r, Theme.gold.g, Theme.gold.b, 0.16)
        border.width: 1
        border.color: Qt.rgba(Theme.gold.r, Theme.gold.g, Theme.gold.b, 0.4)
        width: (root.width - 8) / 3
        x: 4 + Theme.mode * width
        Behavior on x { NumberAnimation { duration: Theme.durBase; easing.type: Easing.OutBack; easing.overshoot: 1.05 } }
    }

    Row {
        id: row
        anchors.centerIn: parent
        Repeater {
            model: Theme.modeLabels
            Item {
                width: (root.width - 8) / 3
                height: root.height
                Text {
                    anchors.centerIn: parent
                    text: root.compact ? modelData.charAt(0) : modelData
                    color: index === Theme.mode ? Theme.gold : Theme.textMuted
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeMicro
                    font.weight: index === Theme.mode ? Font.DemiBold : Font.Medium
                    Behavior on color { ColorAnimation { duration: Theme.durFast } }
                }
                HoverHandler { cursorShape: Qt.PointingHandCursor }
                TapHandler { onTapped: Theme.mode = index }
            }
        }
    }
}
