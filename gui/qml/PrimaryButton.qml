import QtQuick
import QtQuick.Controls.Basic
import VaultGuard

// Gold CTA — flat gold gradient, brighter on hover, press-scale, loading state.
// One per screen — the single primary action.
Button {
    id: control
    property bool loading: false
    property string iconName: ""
    property color tone: Theme.gold
    property color toneSoft: Theme.goldSoft
    implicitHeight: 50
    implicitWidth: Math.max(160, contentItem.implicitWidth + 56)
    enabled: !loading
    font.family: Theme.fontBody
    font.pixelSize: Theme.sizeBody
    font.weight: Font.DemiBold
    hoverEnabled: true

    contentItem: Item {
        implicitWidth: row.implicitWidth
        Row {
            id: row
            anchors.centerIn: parent
            spacing: Theme.sm
            BusyIndicator {
                running: control.loading
                visible: control.loading
                implicitWidth: 18; implicitHeight: 18
                anchors.verticalCenter: parent.verticalCenter
            }
            Icon {
                visible: !control.loading && control.iconName.length > 0
                name: control.iconName
                size: 18
                color: Theme.textOnGold
                anchors.verticalCenter: parent.verticalCenter
            }
            Text {
                text: control.text
                color: Theme.textOnGold
                font: control.font
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    background: Rectangle {
        radius: Theme.radiusSm
        opacity: control.enabled ? 1.0 : 0.5
        gradient: Gradient {
            GradientStop { position: 0.0; color: control.hovered
                           ? Qt.lighter(control.toneSoft, 1.08) : control.toneSoft }
            GradientStop { position: 1.0; color: control.hovered
                           ? Qt.lighter(control.tone, 1.06) : control.tone }
        }
        // Top highlight line for a crisp, lit edge — flat, no blur.
        Rectangle {
            anchors { left: parent.left; right: parent.right; top: parent.top }
            anchors.margins: 1
            height: 1
            color: Qt.rgba(1, 1, 1, 0.35)
        }
        Behavior on scale { NumberAnimation { duration: Theme.durFast; easing.type: Easing.OutCubic } }
        scale: control.down ? 0.97 : 1.0
    }

    HoverHandler { cursorShape: Qt.PointingHandCursor }
}
