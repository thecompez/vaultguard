import QtQuick
import VaultGuard

// Persistent left navigation for the unlocked vault. Vector glyphs (no emoji),
// active item highlighted with a gold indicator bar. Top section (brand + nav)
// anchors to the top; the footer (theme + device + lock) anchors to the bottom,
// so nothing is ever clipped regardless of window height.
Rectangle {
    id: root
    property int current: 0
    signal navigate(int index)
    signal lockRequested()

    width: 240
    color: Theme.isDark ? Qt.rgba(1, 1, 1, 0.025) : Qt.rgba(1, 1, 1, 0.45)
    Behavior on color { ColorAnimation { duration: Theme.durBase } }

    readonly property var items: [
        { key: "vault",    label: "Vault" },
        { key: "store",    label: "Store Wallet" },
        { key: "recover",  label: "Recover" }
    ]

    Rectangle { anchors.right: parent.right; width: 1; height: parent.height; color: Theme.border }

    // ---- Top: brand + navigation ----
    Column {
        id: topSection
        anchors { top: parent.top; left: parent.left; right: parent.right; margins: Theme.md }
        spacing: Theme.xl

        Row {
            spacing: Theme.sm
            leftPadding: Theme.sm
            topPadding: Theme.sm
            Rectangle {
                width: 34; height: 34; radius: 9
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Theme.goldSoft }
                    GradientStop { position: 1.0; color: Theme.gold }
                }
                ShieldGlyph { anchors.centerIn: parent; size: 18; color: Theme.textOnGold }
            }
            Column {
                anchors.verticalCenter: parent.verticalCenter
                Text {
                    text: "VAULTGUARD"
                    color: Theme.text
                    font.family: Theme.fontDisplay
                    font.pixelSize: Theme.sizeSmall
                    font.weight: Font.Bold
                    font.letterSpacing: 1.5
                }
                Text {
                    text: "v1.1 · offline"
                    color: Theme.textFaint
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeMicro
                }
            }
        }

        Column {
            width: parent.width
            spacing: 4
            Repeater {
                model: root.items
                Rectangle {
                    width: parent.width
                    height: 46
                    radius: Theme.radiusSm
                    color: index === root.current ? Theme.surfaceStrong
                            : (hover.hovered ? Theme.surface : "transparent")
                    Behavior on color { ColorAnimation { duration: Theme.durFast } }

                    Rectangle {
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.left: parent.left
                        width: 3; height: 22; radius: 2
                        color: Theme.gold
                        opacity: index === root.current ? 1 : 0
                        Behavior on opacity { NumberAnimation { duration: Theme.durFast } }
                    }
                    Row {
                        anchors.verticalCenter: parent.verticalCenter
                        x: Theme.md
                        spacing: Theme.sm + 2
                        Icon {
                            anchors.verticalCenter: parent.verticalCenter
                            name: modelData.key
                            size: 19
                            color: index === root.current ? Theme.gold : Theme.textMuted
                        }
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: modelData.label
                            color: index === root.current ? Theme.text : Theme.textMuted
                            font.family: Theme.fontBody
                            font.pixelSize: Theme.sizeBody
                            font.weight: index === root.current ? Font.DemiBold : Font.Normal
                        }
                    }
                    HoverHandler { id: hover; cursorShape: Qt.PointingHandCursor }
                    TapHandler { onTapped: root.navigate(index) }
                }
            }
        }
    }

    // ---- Bottom: appearance + device + lock ----
    Column {
        id: footer
        anchors { bottom: parent.bottom; left: parent.left; right: parent.right; margins: Theme.md }
        spacing: Theme.sm

        Text {
            text: "APPEARANCE"
            color: Theme.textFaint
            font.family: Theme.fontBody
            font.pixelSize: Theme.sizeMicro
            font.weight: Font.Bold
            font.letterSpacing: 1.5
        }
        ThemeToggle { width: parent.width }

        Item { width: 1; height: Theme.xs }

        Pill {
            tone: Theme.success
            text: VaultController.deviceName + " · " + VaultController.deviceSize
        }
        GhostButton {
            width: parent.width
            iconName: "lock"; text: "Lock Vault"
            danger: true
            onClicked: root.lockRequested()
        }
    }
}
