import QtQuick
import VaultGuard

// Lightweight stroke-icon set drawn on a Canvas. One consistent visual language
// (1.7px stroke, round caps, 24-unit grid) — no emoji, no raster, theme-tinted.
Canvas {
    id: root
    property string name: ""
    property real size: 20
    property color color: Theme.text
    property real stroke: 1.7
    width: size
    height: size
    onColorChanged: requestPaint()
    onNameChanged: requestPaint()
    onSizeChanged: requestPaint()

    onPaint: {
        var ctx = getContext("2d")
        ctx.reset()
        var s = width / 24
        ctx.scale(s, s)
        ctx.strokeStyle = root.color
        ctx.fillStyle = root.color
        ctx.lineWidth = root.stroke
        ctx.lineCap = "round"
        ctx.lineJoin = "round"

        function line(x1, y1, x2, y2) { ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke() }

        switch (root.name) {
        case "vault": // shield
            ctx.beginPath()
            ctx.moveTo(12, 3); ctx.lineTo(20, 6); ctx.lineTo(20, 12)
            ctx.bezierCurveTo(20, 17, 16.5, 20, 12, 21.5)
            ctx.bezierCurveTo(7.5, 20, 4, 17, 4, 12)
            ctx.lineTo(4, 6); ctx.closePath(); ctx.stroke()
            ctx.beginPath(); ctx.arc(12, 11, 2, 0, Math.PI * 2); ctx.stroke()
            line(12, 13, 12, 16)
            break
        case "store": // plus in box
            ctx.beginPath(); ctx.roundedRect ? ctx.roundedRect(4, 4, 16, 16, 3) : ctx.rect(4, 4, 16, 16); ctx.stroke()
            line(12, 8.5, 12, 15.5); line(8.5, 12, 15.5, 12)
            break
        case "recover": // refresh / counter-clockwise
            ctx.beginPath(); ctx.arc(12, 12, 7, Math.PI * 0.35, Math.PI * 1.85); ctx.stroke()
            ctx.beginPath(); ctx.moveTo(12 + 7 * Math.cos(Math.PI * 0.35), 12 + 7 * Math.sin(Math.PI * 0.35))
            ctx.lineTo(18.5, 12.5); ctx.moveTo(12 + 7 * Math.cos(Math.PI * 0.35), 12 + 7 * Math.sin(Math.PI * 0.35))
            ctx.lineTo(16.5, 16.8); ctx.stroke()
            break
        case "key":
            ctx.beginPath(); ctx.arc(8, 8, 4, 0, Math.PI * 2); ctx.stroke()
            line(10.8, 10.8, 19, 19); line(16.5, 16.5, 18.5, 14.5); line(14, 14, 16, 12)
            break
        case "lock":
            ctx.beginPath(); ctx.rect(5, 11, 14, 9); ctx.stroke()
            ctx.beginPath(); ctx.arc(12, 11, 4, Math.PI, 0); ctx.stroke()
            break
        case "usb":
            line(12, 4, 12, 20)
            ctx.beginPath(); ctx.moveTo(9.5, 6.5); ctx.lineTo(12, 4); ctx.lineTo(14.5, 6.5); ctx.stroke()
            line(12, 10, 8, 12); ctx.beginPath(); ctx.arc(8, 13, 1.4, 0, Math.PI * 2); ctx.fill()
            line(12, 13, 16, 11); ctx.beginPath(); ctx.rect(14.6, 8.6, 3, 2.6); ctx.stroke()
            break
        case "copy":
            ctx.beginPath(); ctx.rect(8, 8, 11, 11); ctx.stroke()
            ctx.beginPath(); ctx.moveTo(5, 15); ctx.lineTo(5, 5); ctx.lineTo(15, 5); ctx.stroke()
            break
        case "check":
            ctx.beginPath(); ctx.moveTo(5, 12.5); ctx.lineTo(10, 17.5); ctx.lineTo(19, 6.5); ctx.stroke()
            break
        case "arrow":
            line(5, 12, 19, 12)
            ctx.beginPath(); ctx.moveTo(13, 6); ctx.lineTo(19, 12); ctx.lineTo(13, 18); ctx.stroke()
            break
        case "coin":
            ctx.beginPath(); ctx.arc(12, 12, 8, 0, Math.PI * 2); ctx.stroke()
            line(12, 7.5, 12, 16.5); line(9.5, 10, 14, 10); line(9.5, 14, 14, 14)
            break
        case "warning":
            ctx.beginPath(); ctx.moveTo(12, 4); ctx.lineTo(21, 19); ctx.lineTo(3, 19); ctx.closePath(); ctx.stroke()
            line(12, 9, 12, 14); ctx.beginPath(); ctx.arc(12, 16.5, 0.9, 0, Math.PI * 2); ctx.fill()
            break
        }
    }
}
