import QtQuick
import QtQuick.Effects
import VaultGuard

// Cinematic base layer: solid themed base + depth gradient + two slowly drifting
// light blobs. Decorative — respects reduced motion via `animated`, and
// cross-fades smoothly when the theme changes.
Item {
    id: root
    property bool animated: true

    // Solid base (animates on theme switch).
    Rectangle {
        anchors.fill: parent
        color: Theme.bgBase
        Behavior on color { ColorAnimation { duration: Theme.durSlow } }
    }

    // Vertical depth: lighter top → darker bottom.
    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: Qt.rgba(1, 1, 1, Theme.isDark ? 0.03 : 0.35) }
            GradientStop { position: 0.5; color: "transparent" }
            GradientStop { position: 1.0; color: Qt.rgba(0, 0, 0, Theme.isDark ? 0.35 : 0.06) }
        }
    }

    // Gold blob (top-left), purple blob (bottom-right).
    Rectangle {
        id: blobA
        width: 540; height: 540; radius: width / 2
        color: Theme.gold
        opacity: Theme.isDark ? 0.10 : 0.16
        x: -160; y: -180
        layer.enabled: true
        layer.effect: MultiEffect { blurEnabled: true; blur: 1.0; blurMax: 64 }
        Behavior on color { ColorAnimation { duration: Theme.durSlow } }
        Behavior on opacity { NumberAnimation { duration: Theme.durSlow } }

        SequentialAnimation on x {
            running: root.animated; loops: Animation.Infinite
            NumberAnimation { to: -60;  duration: 9000; easing.type: Easing.InOutSine }
            NumberAnimation { to: -160; duration: 9000; easing.type: Easing.InOutSine }
        }
    }

    Rectangle {
        id: blobB
        width: 640; height: 640; radius: width / 2
        color: Theme.accent
        opacity: Theme.isDark ? 0.12 : 0.16
        x: root.width - 400; y: root.height - 380
        layer.enabled: true
        layer.effect: MultiEffect { blurEnabled: true; blur: 1.0; blurMax: 72 }
        Behavior on color { ColorAnimation { duration: Theme.durSlow } }
        Behavior on opacity { NumberAnimation { duration: Theme.durSlow } }

        SequentialAnimation on y {
            running: root.animated; loops: Animation.Infinite
            NumberAnimation { to: root.height - 480; duration: 11000; easing.type: Easing.InOutSine }
            NumberAnimation { to: root.height - 380; duration: 11000; easing.type: Easing.InOutSine }
        }
    }

    // Side vignette for depth (subtle, muted in light mode).
    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            orientation: Gradient.Horizontal
            GradientStop { position: 0.0; color: Qt.rgba(0, 0, 0, Theme.isDark ? 0.25 : 0.05) }
            GradientStop { position: 0.5; color: "transparent" }
            GradientStop { position: 1.0; color: Qt.rgba(0, 0, 0, Theme.isDark ? 0.25 : 0.05) }
        }
    }
}
