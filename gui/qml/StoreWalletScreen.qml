import QtQuick
import QtQuick.Layouts
import QtQuick.Controls.Basic
import VaultGuard

// Capture a wallet's details and seal it. Fills the panel: header on top, the
// form scrolls inside a card in the middle, and the action bar is a pinned bar
// BELOW the card (not inside it) so the buttons can never be clipped.
Item {
    id: root
    signal done()
    signal cancelled()
    signal toast(string kind, string message)

    Connections {
        target: VaultController
        function onWalletStored(id) { root.done() }
        function onNotify(kind, message) { root.toast(kind, message) }
    }

    property string currency: "BTC"

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.xl
        spacing: Theme.lg

        // Header.
        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2
            Text {
                text: "Store Wallet"
                color: Theme.text
                font.family: Theme.fontDisplay
                font.pixelSize: Theme.sizeDisplay
                font.weight: Font.Bold
            }
            Text {
                text: "Encrypted with your master password and written across three redundant sectors."
                color: Theme.textMuted
                font.family: Theme.fontBody
                font.pixelSize: Theme.sizeSmall
            }
        }

        // Scrolling form card — fills the space between header and action bar.
        GlassCard {
            Layout.fillWidth: true
            Layout.fillHeight: true

            Flickable {
                id: flick
                anchors.fill: parent
                clip: true
                contentHeight: form.implicitHeight
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

                ColumnLayout {
                    id: form
                    width: flick.width
                    spacing: Theme.md

                    GroupLabel { text: "IDENTITY" }
                    RowLayout {
                        Layout.fillWidth: true
                        spacing: Theme.md
                        VaultTextField {
                            id: idField
                            Layout.fillWidth: true
                            label: "Wallet ID"; required: true; mono: true
                            placeholder: "cold-01"
                            helper: "Letters, numbers, _ or - (max 64)."
                            error: idErr; property string idErr: ""
                            onTextChanged: idErr = ""
                        }
                        VaultTextField {
                            id: nameField
                            Layout.fillWidth: true
                            label: "Display name"; required: true
                            placeholder: "Cold Storage"
                            error: nameErr; property string nameErr: ""
                            onTextChanged: nameErr = ""
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 6
                        Text {
                            text: "Currency"
                            color: Theme.textMuted
                            font.family: Theme.fontBody
                            font.pixelSize: Theme.sizeSmall
                            font.weight: Font.Medium
                        }
                        Flow {
                            Layout.fillWidth: true
                            spacing: Theme.sm
                            Repeater {
                                model: ["BTC", "ETH", "SOL", "USDT", "XMR"]
                                Rectangle {
                                    property bool sel: root.currency === modelData
                                    implicitWidth: 70; implicitHeight: 38; radius: Theme.radiusSm
                                    color: sel ? Qt.rgba(Theme.gold.r, Theme.gold.g, Theme.gold.b, 0.16)
                                               : Theme.surface
                                    border.width: 1
                                    border.color: sel ? Theme.gold : Theme.border
                                    Behavior on border.color { ColorAnimation { duration: Theme.durFast } }
                                    Text {
                                        anchors.centerIn: parent; text: modelData
                                        color: sel ? Theme.gold : Theme.textMuted
                                        font.family: Theme.fontBody
                                        font.pixelSize: Theme.sizeSmall
                                        font.weight: Font.DemiBold
                                    }
                                    HoverHandler { cursorShape: Qt.PointingHandCursor }
                                    TapHandler { onTapped: root.currency = modelData }
                                }
                            }
                        }
                    }

                    Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: Theme.border }

                    GroupLabel { text: "SECRET MATERIAL" }
                    PasswordField {
                        id: keyField
                        Layout.fillWidth: true
                        label: "Private key"; required: true
                        placeholder: "Paste the private key"
                        helper: "Stored encrypted; hidden by default."
                        error: keyErr; property string keyErr: ""
                        onTextChanged: keyErr = ""
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 6
                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "Seed phrase"
                                color: Theme.textMuted
                                font.family: Theme.fontBody
                                font.pixelSize: Theme.sizeSmall
                                font.weight: Font.Medium
                            }
                            Text { text: "*"; color: Theme.gold; font.pixelSize: Theme.sizeSmall }
                            Item { Layout.fillWidth: true }
                            Text {
                                text: seedArea.text.trim().length === 0 ? "" :
                                      (seedArea.text.trim().split(/\s+/).length + " words")
                                color: Theme.textFaint
                                font.family: Theme.fontBody
                                font.pixelSize: Theme.sizeMicro
                            }
                        }
                        Rectangle {
                            Layout.fillWidth: true
                            implicitHeight: 88
                            radius: Theme.radiusSm
                            color: Theme.surface
                            border.width: seedArea.activeFocus ? 2 : 1
                            border.color: seedArea.activeFocus ? Theme.gold : Theme.border
                            Behavior on border.color { ColorAnimation { duration: Theme.durFast } }
                            ScrollView {
                                anchors.fill: parent
                                anchors.margins: Theme.sm
                                TextArea {
                                    id: seedArea
                                    placeholderText: "twelve or twenty-four words, space separated"
                                    placeholderTextColor: Theme.textFaint
                                    color: Theme.text
                                    wrapMode: TextArea.Wrap
                                    font.family: Theme.fontMono
                                    font.pixelSize: Theme.sizeSmall
                                    selectByMouse: true
                                    background: null
                                }
                            }
                        }
                    }
                }
            }
        }

        // Pinned action bar — a sibling of the card, so it is always visible.
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.sm
            GhostButton { text: "Cancel"; onClicked: root.cancelled() }
            Item { Layout.fillWidth: true }
            PrimaryButton {
                iconName: "lock"; text: "Seal into Vault"
                loading: VaultController.busy
                enabled: !VaultController.busy
                onClicked: root.submit(root.currency)
            }
        }
    }

    function submit(currency) {
        var ok = true
        if (!/^[A-Za-z0-9_-]{1,64}$/.test(idField.text)) {
            idField.idErr = "Use letters, numbers, _ or - (max 64)."
            ok = false
        }
        if (nameField.text.trim().length === 0) {
            nameField.nameErr = "Give the wallet a name."
            ok = false
        }
        if (keyField.text.trim().length === 0 && seedArea.text.trim().length === 0) {
            keyField.keyErr = "Provide a private key or a seed phrase."
            ok = false
        }
        if (ok)
            VaultController.storeWallet({
                id: idField.text, name: nameField.text.trim(), currency: currency
            })
    }
}
