import QtQuick
import QtQuick.Layouts
import QtQuick.Controls.Basic
import VaultGuard

// Pick a wallet, re-authenticate, and trigger the one-time reveal dialog.
// Re-asking for the password before showing plaintext is a deliberate gate.
Item {
    id: root
    property string preselect: ""
    signal revealReady(var secret)
    signal toast(string kind, string message)

    onPreselectChanged: if (preselect.length) selected = preselect
    property string selected: ""

    Connections {
        target: VaultController
        function onSecretRevealed(secret) { root.revealReady(secret) }
        function onNotify(kind, message) { root.toast(kind, message) }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.xl
        spacing: Theme.lg

        ColumnLayout {
            spacing: 2
            Text {
                text: "Recover Wallet"
                color: Theme.text
                font.family: Theme.fontDisplay
                font.pixelSize: Theme.sizeDisplay
                font.weight: Font.Bold
            }
            Text {
                text: "Select a wallet and confirm your password to reveal it once."
                color: Theme.textMuted
                font.family: Theme.fontBody
                font.pixelSize: Theme.sizeSmall
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Theme.lg

            // Wallet picker list.
            GlassCard {
                Layout.preferredWidth: 360
                Layout.fillHeight: true
                ColumnLayout {
                    anchors.fill: parent
                    spacing: Theme.sm
                    GroupLabel { text: "SELECT WALLET" }
                    ListView {
                        id: list
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        clip: true
                        spacing: 6
                        model: VaultController.wallets
                        delegate: Rectangle {
                            width: list.width
                            height: 60
                            radius: Theme.radiusSm
                            property bool sel: root.selected === modelData.id
                            color: sel ? Theme.surfaceStrong
                                   : (rowHover.hovered ? Theme.surface : "transparent")
                            border.width: 1
                            border.color: sel ? Theme.gold : "transparent"
                            Behavior on color { ColorAnimation { duration: Theme.durFast } }
                            Behavior on border.color { ColorAnimation { duration: Theme.durFast } }
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: Theme.md
                                anchors.rightMargin: Theme.md
                                spacing: Theme.sm
                                ColumnLayout {
                                    spacing: 0
                                    Text {
                                        text: modelData.name
                                        color: Theme.text
                                        font.family: Theme.fontBody
                                        font.pixelSize: Theme.sizeBody
                                        font.weight: Font.DemiBold
                                    }
                                    Text {
                                        text: modelData.id
                                        color: Theme.textFaint
                                        font.family: Theme.fontMono
                                        font.pixelSize: Theme.sizeMicro
                                    }
                                }
                                Item { Layout.fillWidth: true }
                                Pill { text: modelData.currency; tone: Theme.accent; dot: false }
                            }
                            HoverHandler { id: rowHover; cursorShape: Qt.PointingHandCursor }
                            TapHandler { onTapped: root.selected = modelData.id }
                        }

                        // Empty state inside the list.
                        Text {
                            anchors.centerIn: parent
                            visible: list.count === 0
                            text: "No wallets to recover yet."
                            color: Theme.textMuted
                            font.family: Theme.fontBody
                            font.pixelSize: Theme.sizeSmall
                        }
                    }
                }
            }

            // Confirm + reveal panel.
            GlassCard {
                Layout.fillWidth: true
                Layout.fillHeight: true
                ColumnLayout {
                    anchors.fill: parent
                    spacing: Theme.lg

                    GroupLabel { text: "CONFIRM IDENTITY" }

                    Rectangle {
                        Layout.fillWidth: true
                        radius: Theme.radiusSm
                        color: Theme.surface
                        border.color: Theme.border; border.width: 1
                        implicitHeight: 56
                        visible: root.selected.length > 0
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            x: Theme.md
                            text: "Selected · " + root.selected
                            color: Theme.text
                            font.family: Theme.fontMono
                            font.pixelSize: Theme.sizeSmall
                        }
                    }

                    PasswordField {
                        id: confirmPw
                        Layout.fillWidth: true
                        label: "Master password"
                        placeholder: "Re-enter to authorize reveal"
                        helper: "Required every time plaintext is shown."
                        error: pwErr; property string pwErr: ""
                        onTextChanged: pwErr = ""
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        radius: Theme.radiusSm
                        color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.08)
                        border.color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.25)
                        border.width: 1
                        implicitHeight: hintText.implicitHeight + Theme.md
                        Text {
                            id: hintText
                            anchors.centerIn: parent
                            width: parent.width - Theme.lg
                            text: "The secret is shown once in a panel that auto-hides. Prefer the "
                                  + "one-time view over exporting a plaintext file."
                            wrapMode: Text.WordWrap
                            color: Theme.accentSoft
                            font.family: Theme.fontBody
                            font.pixelSize: Theme.sizeMicro
                        }
                    }

                    Item { Layout.fillHeight: true }

                    PrimaryButton {
                        Layout.fillWidth: true
                        iconName: "key"; text: "Reveal Once"
                        loading: VaultController.busy
                        enabled: !VaultController.busy
                        onClicked: root.submit()
                    }
                }
            }
        }
    }

    function submit() {
        if (root.selected.length === 0) {
            root.toast("error", "Select a wallet first.")
            return
        }
        if (confirmPw.text.length < 4) {
            confirmPw.pwErr = "Enter your master password."
            return
        }
        VaultController.reveal(root.selected, confirmPw.text)
        confirmPw.text = ""
    }
}
