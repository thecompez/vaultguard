import QtQuick
import QtQuick.Layouts
import VaultGuard

// Vault overview: stats strip + the wallet collection (or an empty state).
Item {
    id: root
    signal storeRequested()
    signal recoverRequested(string walletId)

    readonly property var currencyTone: ({
        "BTC": "#F7931A", "ETH": "#8B5CF6", "SOL": "#34D399",
        "USDT": "#26A17B", "XMR": "#FF6600"
    })

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.xl
        spacing: Theme.lg

        // Header row.
        RowLayout {
            Layout.fillWidth: true
            ColumnLayout {
                spacing: 2
                Text {
                    text: "Your Vault"
                    color: Theme.text
                    font.family: Theme.fontDisplay
                    font.pixelSize: Theme.sizeDisplay
                    font.weight: Font.Bold
                }
                Text {
                    text: "Encrypted at rest · Argon2id + XChaCha20-Poly1305"
                    color: Theme.textMuted
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeSmall
                }
            }
            Item { Layout.fillWidth: true }
            PrimaryButton { iconName: "store"; text: "Store Wallet"; onClicked: root.storeRequested() }
        }

        // Stats strip.
        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.md
            Repeater {
                model: [
                    { k: "Wallets",  v: "" + VaultController.wallets.length, tone: Theme.gold },
                    { k: "Redundant copies", v: "3× sectors", tone: Theme.accent },
                    { k: "Device", v: VaultController.deviceName, tone: Theme.success }
                ]
                GlassCard {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 92
                    ColumnLayout {
                        anchors.fill: parent
                        spacing: 4
                        Text {
                            text: modelData.k
                            color: Theme.textMuted
                            font.family: Theme.fontBody
                            font.pixelSize: Theme.sizeMicro
                            font.weight: Font.Medium
                        }
                        Text {
                            text: modelData.v
                            color: modelData.tone
                            font.family: Theme.fontDisplay
                            font.pixelSize: Theme.sizeH1
                            font.weight: Font.Bold
                        }
                    }
                }
            }
        }

        // Collection header.
        Text {
            text: "WALLETS"
            color: Theme.textFaint
            font.family: Theme.fontBody
            font.pixelSize: Theme.sizeMicro
            font.weight: Font.Bold
            font.letterSpacing: 1.5
        }

        // Empty state.
        GlassCard {
            visible: VaultController.wallets.length === 0
            Layout.fillWidth: true
            Layout.preferredHeight: 220
            ColumnLayout {
                anchors.centerIn: parent
                spacing: Theme.md
                Rectangle {
                    Layout.alignment: Qt.AlignHCenter
                    implicitWidth: 56; implicitHeight: 56; radius: 16
                    color: Theme.surface
                    border.color: Theme.border; border.width: 1
                    ShieldGlyph { anchors.centerIn: parent; size: 28; color: Theme.textMuted }
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: "No wallets stored yet"
                    color: Theme.text
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeH2
                    font.weight: Font.DemiBold
                }
                Text {
                    Layout.alignment: Qt.AlignHCenter
                    text: "Seal your first private key or seed phrase into the vault."
                    color: Theme.textMuted
                    font.family: Theme.fontBody
                    font.pixelSize: Theme.sizeSmall
                }
                PrimaryButton {
                    Layout.alignment: Qt.AlignHCenter
                    iconName: "store"; text: "Store a Wallet"
                    onClicked: root.storeRequested()
                }
            }
        }

        // Wallet grid.
        GridView {
            id: grid
            visible: VaultController.wallets.length > 0
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            cellWidth: width / Math.max(1, Math.floor(width / 300))
            cellHeight: 132
            model: VaultController.wallets

            delegate: Item {
                width: grid.cellWidth
                height: grid.cellHeight
                GlassCard {
                    id: walletCard
                    anchors.fill: parent
                    anchors.margins: Theme.sm
                    property color tone: root.currencyTone[modelData.currency] || Theme.accent

                    ColumnLayout {
                        anchors.fill: parent
                        spacing: Theme.sm
                        RowLayout {
                            Layout.fillWidth: true
                            Rectangle {
                                implicitWidth: 40; implicitHeight: 40; radius: 11
                                color: Qt.rgba(walletCard.tone.r, walletCard.tone.g,
                                               walletCard.tone.b, 0.18)
                                Text {
                                    anchors.centerIn: parent
                                    text: modelData.currency
                                    color: walletCard.tone
                                    font.family: Theme.fontDisplay
                                    font.pixelSize: Theme.sizeMicro
                                    font.weight: Font.Bold
                                }
                            }
                            ColumnLayout {
                                spacing: 0
                                Text {
                                    text: modelData.name
                                    color: Theme.text
                                    font.family: Theme.fontBody
                                    font.pixelSize: Theme.sizeBody
                                    font.weight: Font.DemiBold
                                    elide: Text.ElideRight
                                    Layout.fillWidth: true
                                }
                                Text {
                                    text: modelData.id
                                    color: Theme.textFaint
                                    font.family: Theme.fontMono
                                    font.pixelSize: Theme.sizeMicro
                                }
                            }
                            Item { Layout.fillWidth: true }
                        }
                        Item { Layout.fillHeight: true }
                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                text: "Added " + modelData.createdAt
                                color: Theme.textFaint
                                font.family: Theme.fontBody
                                font.pixelSize: Theme.sizeMicro
                            }
                            Item { Layout.fillWidth: true }
                            GhostButton {
                                iconName: "key"; text: "Reveal"
                                implicitHeight: 34
                                onClicked: root.recoverRequested(modelData.id)
                            }
                        }
                    }
                }
            }
        }
    }
}
