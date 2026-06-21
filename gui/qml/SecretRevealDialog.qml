import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Layouts
import VaultGuard

// One-time secret reveal. Strong scrim, blurred-glass sheet, copy-to-clipboard,
// and an explicit auto-hide countdown so plaintext is never left on screen.
Item {
    id: root
    anchors.fill: parent
    visible: scrim.opacity > 0.01
    z: 900

    property var secret: null
    property int secondsLeft: 0

    signal exportRequested(string walletId)

    function open(s) {
        secret = s
        secondsLeft = 30
        sheet.scale = 0.94
        showAnim.restart()
        countdown.restart()
    }
    function close() {
        countdown.stop()
        hideAnim.restart()
    }

    // Scrim — dismiss on click outside.
    Rectangle {
        id: scrim
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.62)
        opacity: 0
        TapHandler { onTapped: root.close() }
    }

    GlassCard {
        id: sheet
        anchors.centerIn: parent
        width: 560
        height: body.implicitHeight + Theme.xl * 2
        fill: Theme.bgElevated
        opacity: scrim.opacity
        transformOrigin: Item.Center

        ColumnLayout {
            id: body
            anchors.fill: parent
            spacing: Theme.md

            RowLayout {
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: 2
                    Text {
                        text: "One-time reveal"
                        color: Theme.text
                        font.family: Theme.fontDisplay
                        font.pixelSize: Theme.sizeH2
                        font.weight: Font.Bold
                    }
                    Text {
                        text: root.secret ? root.secret.name + "  ·  " + root.secret.id : ""
                        color: Theme.textMuted
                        font.family: Theme.fontBody
                        font.pixelSize: Theme.sizeSmall
                    }
                }
                Item { Layout.fillWidth: true }
                Pill {
                    tone: root.secondsLeft <= 8 ? Theme.danger : Theme.warning
                    dot: false
                    text: "Hides in " + root.secondsLeft + "s"
                }
            }

            Rectangle {
                Layout.fillWidth: true; implicitHeight: 1; color: Theme.border
            }

            SecretRow {
                Layout.fillWidth: true
                caption: "Private Key"
                value: root.secret ? root.secret.privateKey : ""
                onCopied: toastRelay.show("ok", "Private key copied to clipboard")
            }
            SecretRow {
                Layout.fillWidth: true
                caption: "Seed Phrase"
                value: root.secret ? root.secret.seedPhrase : ""
                wrap: true
                onCopied: toastRelay.show("ok", "Seed phrase copied to clipboard")
            }

            Rectangle {
                Layout.fillWidth: true
                radius: Theme.radiusSm
                color: Qt.rgba(Theme.warning.r, Theme.warning.g, Theme.warning.b, 0.10)
                border.color: Qt.rgba(Theme.warning.r, Theme.warning.g, Theme.warning.b, 0.3)
                border.width: 1
                implicitHeight: warn.implicitHeight + Theme.md
                Text {
                    id: warn
                    anchors.centerIn: parent
                    width: parent.width - Theme.lg
                    text: "Anyone with these values controls the funds. Never paste them into "
                          + "an online device. This panel auto-hides and keeps no copy."
                    wrapMode: Text.WordWrap
                    color: Theme.warning
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeMicro
                }
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.sm
                GhostButton {
                    text: "Export plaintext (risky)"
                    danger: true
                    onClicked: { root.exportRequested(root.secret.id); root.close() }
                }
                Item { Layout.fillWidth: true }
                PrimaryButton {
                    text: "Done — hide now"
                    onClicked: root.close()
                }
            }
        }
    }

    Timer {
        id: countdown
        interval: 1000; repeat: true
        onTriggered: {
            root.secondsLeft--
            if (root.secondsLeft <= 0) root.close()
        }
    }

    // Reveal: scrim fades, sheet springs up from trigger.
    ParallelAnimation {
        id: showAnim
        NumberAnimation { target: scrim; property: "opacity"; to: 1; duration: Theme.durBase }
        NumberAnimation { target: sheet; property: "scale"; to: 1.0
            duration: Theme.durSlow; easing.type: Easing.OutBack; easing.overshoot: 1.1 }
    }
    ParallelAnimation {
        id: hideAnim
        NumberAnimation { target: scrim; property: "opacity"; to: 0; duration: Theme.durFast }
        NumberAnimation { target: sheet; property: "scale"; to: 0.96; duration: Theme.durFast }
    }

    // Lets nested rows raise toasts without knowing the app root.
    signal toast(string kind, string message)
    QtObject {
        id: toastRelay
        function show(k, m) { root.toast(k, m) }
    }
}
