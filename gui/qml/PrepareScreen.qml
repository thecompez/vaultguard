import QtQuick
import QtQuick.Layouts
import QtQuick.Controls.Basic
import VaultGuard

// Format a USB drive into a VaultGuard vault. Destructive — guarded by an
// explicit typed confirmation matching the device name. Centered card that
// caps to the window height: header fixed, form scrolls, actions pinned.
Item {
    id: root
    signal done()
    signal cancelled()
    signal toast(string kind, string message)

    Connections {
        target: VaultController
        function onNotify(kind, message) {
            root.toast(kind, message)
            if (kind === "ok") root.done()
        }
    }

    GlassCard {
        id: card
        anchors.centerIn: parent
        width: Math.min(580, root.width - Theme.xl * 2)
        // Natural height, but never taller than the window.
        readonly property real natural: Theme.lg * 2 + hdr.implicitHeight
                                        + body.implicitHeight + footer.implicitHeight
                                        + col.spacing * 3 + 1
        height: Math.min(natural, root.height - Theme.lg * 2)

        ColumnLayout {
            id: col
            anchors.fill: parent
            spacing: Theme.md

            ColumnLayout {
                id: hdr
                Layout.fillWidth: true
                spacing: 4
                Text {
                    text: "Prepare USB Vault"
                    color: Theme.text
                    font.family: Theme.fontDisplay
                    font.pixelSize: Theme.sizeH1
                    font.weight: Font.Bold
                }
                Text {
                    text: "Formats the selected drive to APFS and seeds the encrypted "
                          + "sector chain. All existing data on the drive is erased."
                    color: Theme.textMuted
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeSmall
                }
            }

            Flickable {
                id: flick
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                contentHeight: body.implicitHeight
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                ColumnLayout {
                    id: body
                    width: flick.width
                    spacing: Theme.md

                    // Detected device summary.
                    Rectangle {
                        Layout.fillWidth: true
                        radius: Theme.radiusSm
                        color: Theme.surface
                        border.color: Theme.border; border.width: 1
                        implicitHeight: 64
                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: Theme.md
                            anchors.rightMargin: Theme.md
                            spacing: Theme.md
                            Rectangle {
                                implicitWidth: 38; implicitHeight: 38; radius: 9
                                color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
                                Text {
                                    anchors.centerIn: parent; text: "USB"
                                    color: Theme.accentSoft
                                    font.family: Theme.fontDisplay
                                    font.pixelSize: Theme.sizeMicro; font.weight: Font.Bold
                                }
                            }
                            ColumnLayout {
                                spacing: 0
                                Text {
                                    text: VaultController.mountPath
                                    color: Theme.text
                                    font.family: Theme.fontMono
                                    font.pixelSize: Theme.sizeSmall
                                }
                                Text {
                                    text: VaultController.deviceSize + " · external"
                                    color: Theme.textFaint
                                    font.family: Theme.fontBody
                                    font.pixelSize: Theme.sizeMicro
                                }
                            }
                            Item { Layout.fillWidth: true }
                            Pill { tone: Theme.success; text: "Detected" }
                        }
                    }

                    VaultTextField {
                        id: nameField
                        Layout.fillWidth: true
                        label: "Vault name"
                        required: true
                        placeholder: "VAULT-PRO"
                        helper: "Letters, digits, dot, dash, underscore (max 32)."
                        error: nameError
                        property string nameError: ""
                        onTextChanged: nameError = ""
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: Theme.sm
                        RowLayout {
                            Layout.fillWidth: true
                            PasswordField {
                                id: pwField
                                Layout.fillWidth: true
                                label: "Master password"
                                required: true
                                placeholder: "Create a strong password"
                                error: pwError
                                property string pwError: ""
                                onTextChanged: pwError = ""
                            }
                            GhostButton {
                                text: "Generate"
                                Layout.alignment: Qt.AlignBottom
                                onClicked: {
                                    var g = VaultController.generatePassword()
                                    pwField.text = g
                                    pwField.revealed = true
                                    root.toast("ok", "Strong password generated — store it safely.")
                                }
                            }
                        }
                        PasswordStrength { Layout.fillWidth: true; password: pwField.text }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        radius: Theme.radiusSm
                        color: Qt.rgba(Theme.dangerDeep.r, Theme.dangerDeep.g, Theme.dangerDeep.b, 0.10)
                        border.color: Qt.rgba(Theme.dangerDeep.r, Theme.dangerDeep.g, Theme.dangerDeep.b, 0.35)
                        border.width: 1
                        implicitHeight: confirmCol.implicitHeight + Theme.md
                        ColumnLayout {
                            id: confirmCol
                            anchors.fill: parent
                            anchors.margins: Theme.sm + 2
                            spacing: Theme.sm
                            Text {
                                text: "This erases everything on the drive and cannot be undone."
                                color: Theme.danger
                                font.family: Theme.fontBody
                                font.pixelSize: Theme.sizeSmall
                                font.weight: Font.Medium
                            }
                            VaultTextField {
                                id: confirmField
                                Layout.fillWidth: true
                                placeholder: "Type the vault name to confirm"
                                helper: "Confirmation must match the vault name above."
                            }
                        }
                    }
                }
            }

            // Pinned action bar.
            Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: Theme.border }
            RowLayout {
                id: footer
                Layout.fillWidth: true
                spacing: Theme.sm
                GhostButton { text: "Cancel"; onClicked: root.cancelled() }
                Item { Layout.fillWidth: true }
                PrimaryButton {
                    iconName: "usb"; text: "Format & Initialize"
                    loading: VaultController.busy
                    enabled: !VaultController.busy
                    onClicked: root.submit()
                }
            }
        }
    }

    function submit() {
        var ok = true
        if (!/^[A-Za-z0-9._-]{1,32}$/.test(nameField.text)) {
            nameField.nameError = "Invalid name. Use letters, digits, . - _ (max 32)."
            ok = false
        }
        if (pwField.text.length < 8) {
            pwField.pwError = "Use at least 8 characters."
            ok = false
        }
        if (confirmField.text !== nameField.text || nameField.text.length === 0) {
            root.toast("error", "Confirmation does not match the vault name.")
            ok = false
        }
        if (ok) VaultController.prepareUsb(nameField.text, pwField.text)
    }
}
