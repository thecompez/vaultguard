import QtQuick
import QtQuick.Layouts
import VaultGuard

// Entry gate. Detected-USB case = enter password; otherwise route to Prepare.
Item {
    id: root
    signal unlocked()
    signal prepareRequested()
    signal toast(string kind, string message)

    Connections {
        target: VaultController
        function onUnlockResult(ok) { if (ok) root.unlocked() }
        function onNotify(kind, message) { root.toast(kind, message) }
    }

    GlassCard {
        anchors.centerIn: parent
        width: 440
        height: col.implicitHeight + Theme.xl * 2

        ColumnLayout {
            id: col
            anchors.fill: parent
            spacing: Theme.lg

            // Crest.
            ColumnLayout {
                Layout.alignment: Qt.AlignHCenter
                spacing: Theme.sm
                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    implicitWidth: 72; implicitHeight: 72; radius: 20
                    gradient: Gradient {
                        GradientStop { position: 0.0; color: Theme.goldSoft }
                        GradientStop { position: 1.0; color: Theme.gold }
                    }
                    ShieldGlyph { anchors.centerIn: parent; size: 38; color: Theme.textOnGold }
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: "VAULTGUARD"
                    color: Theme.text
                    font.family: Theme.fontDisplay
                    font.pixelSize: Theme.sizeH1
                    font.weight: Font.Bold
                    font.letterSpacing: 2
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: VaultController.deviceDetected
                          ? "Vault detected on " + VaultController.deviceName
                          : "No vault drive detected"
                    color: Theme.textMuted
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeSmall
                }
            }

            // Unlock path.
            ColumnLayout {
                visible: VaultController.deviceDetected
                Layout.fillWidth: true
                spacing: Theme.md

                PasswordField {
                    id: pw
                    Layout.fillWidth: true
                    label: "Master password"
                    placeholder: "Enter your vault password"
                    helper: "Derived with Argon2id. Never leaves this device."
                    error: errorText
                    property string errorText: ""
                    onTextChanged: errorText = ""
                    inputField.onAccepted: submit()
                }

                PrimaryButton {
                    Layout.fillWidth: true
                    iconName: "vault"; text: "Unlock Vault"
                    loading: VaultController.busy
                    onClicked: root.submit()
                }
            }

            // Prepare path.
            ColumnLayout {
                visible: !VaultController.deviceDetected
                Layout.fillWidth: true
                spacing: Theme.md
                Text {
                    Layout.fillWidth: true
                    text: "Insert a USB drive and prepare it as an encrypted vault to begin."
                    color: Theme.textMuted
                    wrapMode: Text.WordWrap
                    horizontalAlignment: Text.AlignHCenter
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeSmall
                }
                PrimaryButton {
                    Layout.fillWidth: true
                    iconName: "usb"; text: "Prepare a USB Vault"
                    onClicked: root.prepareRequested()
                }
            }

            // Offline reminder.
            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                spacing: 6
                Rectangle { implicitWidth: 6; implicitHeight: 6; radius: 3; color: Theme.success }
                Text {
                    text: "Run offline on a trusted machine (e.g. Tails OS)"
                    color: Theme.textFaint
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeMicro
                }
            }
        }
    }

    function submit() {
        if (pw.text.length < 4) {
            pw.errorText = "Password must be at least 4 characters."
            return
        }
        VaultController.unlock(pw.text)
    }
}
