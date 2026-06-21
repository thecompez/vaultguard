import QtQuick
import VaultGuard

// Frosted-glass panel — flat by design. Depth comes from fill contrast, a
// hairline border and a top-edge sheen (a faint inner highlight line), not from
// drop shadows. Renders identically on every backend; never flares into a glow.
Item {
    id: root
    default property alias content: inner.data
    property int radius: Theme.radius
    property color fill: Theme.glass
    // Kept for API compatibility; flat design ignores these.
    property bool glow: false
    property color glowColor: Theme.goldGlow

    Rectangle {
        id: base
        anchors.fill: parent
        radius: root.radius
        color: root.fill
        border.width: 1
        border.color: Theme.border
        Behavior on color { ColorAnimation { duration: Theme.durBase } }
        Behavior on border.color { ColorAnimation { duration: Theme.durBase } }

        // Soft vertical sheen fading down from the top for subtle dimensionality.
        // Clipped to the rounded shape so it never overshoots the corners.
        Rectangle {
            anchors { left: parent.left; right: parent.right; top: parent.top }
            anchors.margins: 1
            height: Math.min(parent.height * 0.4, 110)
            radius: root.radius
            gradient: Gradient {
                GradientStop { position: 0.0; color: Theme.sheen }
                GradientStop { position: 1.0; color: "transparent" }
            }
        }
    }

    Item {
        id: inner
        anchors.fill: parent
        anchors.margins: Theme.lg
    }
}
