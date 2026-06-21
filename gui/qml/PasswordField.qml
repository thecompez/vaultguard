import QtQuick
import QtQuick.Controls.Basic
import VaultGuard

// Password input with show/hide toggle. Built on VaultTextField so it shares
// label/error/focus behavior.
VaultTextField {
    id: root
    property bool revealed: false
    echoMode: revealed ? TextInput.Normal : TextInput.Password
    inputField.rightPadding: 48
    inputField.font.family: revealed ? Theme.fontMono : Theme.fontBody

    // Eye toggle pinned to the field's right edge.
    Item {
        parent: root.inputField
        width: 40; height: parent.height
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter

        Text {
            anchors.centerIn: parent
            text: root.revealed ? "🙈" : "👁"
            font.pixelSize: 18
            color: Theme.textMuted
            visible: false   // glyph fallback hidden; we draw an SVG-style eye below
        }

        // Minimal vector eye (open/closed) to avoid emoji as a control icon.
        Canvas {
            id: eye
            anchors.centerIn: parent
            width: 22; height: 22
            property bool open: root.revealed
            onOpenChanged: requestPaint()
            onPaint: {
                var ctx = getContext("2d")
                ctx.reset()
                ctx.strokeStyle = Qt.rgba(Theme.textMuted.r, Theme.textMuted.g, Theme.textMuted.b, 1)
                ctx.lineWidth = 1.6
                ctx.lineCap = "round"
                var cx = width / 2, cy = height / 2
                ctx.beginPath()
                ctx.moveTo(cx - 9, cy)
                ctx.bezierCurveTo(cx - 4, cy - 6, cx + 4, cy - 6, cx + 9, cy)
                ctx.bezierCurveTo(cx + 4, cy + 6, cx - 4, cy + 6, cx - 9, cy)
                ctx.stroke()
                ctx.beginPath()
                ctx.arc(cx, cy, 2.6, 0, Math.PI * 2)
                ctx.stroke()
                if (!open) {
                    ctx.beginPath()
                    ctx.moveTo(cx - 9, cy - 7)
                    ctx.lineTo(cx + 9, cy + 7)
                    ctx.stroke()
                }
            }
        }

        TapHandler { onTapped: root.revealed = !root.revealed }
        HoverHandler { cursorShape: Qt.PointingHandCursor }
    }
}
