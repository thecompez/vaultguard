import QtQuick
import VaultGuard

// Vector shield-with-keyhole mark. Crisp at any size, theme-tintable —
// never an emoji or raster asset.
Canvas {
    id: root
    property real size: 20
    property color color: Theme.gold
    width: size; height: size
    onColorChanged: requestPaint()
    onPaint: {
        var ctx = getContext("2d")
        ctx.reset()
        var w = width, h = height
        ctx.fillStyle = root.color
        // Shield outline.
        ctx.beginPath()
        ctx.moveTo(w * 0.5, h * 0.06)
        ctx.lineTo(w * 0.9, h * 0.22)
        ctx.lineTo(w * 0.9, h * 0.52)
        ctx.bezierCurveTo(w * 0.9, h * 0.78, w * 0.72, h * 0.9, w * 0.5, h * 0.97)
        ctx.bezierCurveTo(w * 0.28, h * 0.9, w * 0.1, h * 0.78, w * 0.1, h * 0.52)
        ctx.lineTo(w * 0.1, h * 0.22)
        ctx.closePath()
        ctx.fill()
        // Keyhole punched out.
        ctx.globalCompositeOperation = "destination-out"
        ctx.beginPath()
        ctx.arc(w * 0.5, h * 0.45, w * 0.11, 0, Math.PI * 2)
        ctx.fill()
        ctx.beginPath()
        ctx.moveTo(w * 0.44, h * 0.47)
        ctx.lineTo(w * 0.56, h * 0.47)
        ctx.lineTo(w * 0.53, h * 0.7)
        ctx.lineTo(w * 0.47, h * 0.7)
        ctx.closePath()
        ctx.fill()
    }
}
