import QtQuick
import VaultGuard

// Four-segment strength meter with a text verdict. Heuristic only — the real
// entropy gate lives in the crypto core; this is user guidance.
Column {
    id: root
    property string password: ""
    spacing: 6
    width: parent ? parent.width : 320

    readonly property int score: {
        var p = password, s = 0
        if (!p) return 0
        if (p.length >= 8) s++
        if (p.length >= 14) s++
        if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++
        if (/[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)) s++
        return Math.min(s, 4)
    }
    readonly property var labels: ["", "Weak", "Fair", "Strong", "Excellent"]
    readonly property var tones: ["transparent", Theme.danger, Theme.warning,
                                  Theme.goldSoft, Theme.success]

    Row {
        width: parent.width
        spacing: 6
        Repeater {
            model: 4
            Rectangle {
                width: (root.width - 18) / 4
                height: 5
                radius: 3
                color: index < root.score ? root.tones[root.score]
                                          : Qt.rgba(1, 1, 1, 0.08)
                Behavior on color { ColorAnimation { duration: Theme.durFast } }
            }
        }
    }

    Text {
        visible: root.password.length > 0
        text: root.labels[root.score]
        color: root.tones[root.score]
        font.family: Theme.fontBody
        font.pixelSize: Theme.sizeMicro
        font.weight: Font.Medium
    }
}
