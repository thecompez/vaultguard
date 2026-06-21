import QtQuick
import VaultGuard

// Transient feedback that slides in from the top, auto-dismisses, and
// announces via an aria-live-equivalent (does not steal focus).
Item {
    id: root
    anchors.fill: parent
    z: 1000

    property string kind: "ok"
    readonly property color tone: kind === "error" ? Theme.danger
                                  : kind === "warn" ? Theme.warning : Theme.success

    function show(k, message) {
        root.kind = k
        label.text = message
        anim.restart()
    }

    // Holder animates position/opacity; shadow and bar are separate so the
    // text never ghosts into the shadow.
    Item {
        id: holder
        anchors.horizontalCenter: parent.horizontalCenter
        y: -64
        opacity: 0
        width: Math.min(540, label.implicitWidth + 96)
        height: 52

        Rectangle {
            anchors.fill: parent
            radius: Theme.radiusSm
            color: Theme.bgElevated
            border.width: 1
            border.color: Qt.rgba(root.tone.r, root.tone.g, root.tone.b, 0.45)

            Row {
                anchors.fill: parent
                anchors.leftMargin: Theme.md
                anchors.rightMargin: Theme.md
                spacing: Theme.sm
                Rectangle {
                    width: 8; height: 8; radius: 4
                    anchors.verticalCenter: parent.verticalCenter
                    color: root.tone
                }
                Text {
                    id: label
                    anchors.verticalCenter: parent.verticalCenter
                    color: Theme.text
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeSmall
                    width: holder.width - 48
                    wrapMode: Text.WordWrap
                }
            }
        }
    }

    SequentialAnimation {
        id: anim
        ParallelAnimation {
            NumberAnimation { target: holder; property: "y"; to: Theme.lg
                duration: Theme.durBase; easing.type: Easing.OutCubic }
            NumberAnimation { target: holder; property: "opacity"; to: 1
                duration: Theme.durBase }
        }
        PauseAnimation { duration: 3200 }
        ParallelAnimation {
            NumberAnimation { target: holder; property: "y"; to: -64
                duration: Theme.durFast; easing.type: Easing.InCubic }
            NumberAnimation { target: holder; property: "opacity"; to: 0
                duration: Theme.durFast }
        }
    }
}
