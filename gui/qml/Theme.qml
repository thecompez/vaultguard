pragma Singleton
import QtQuick

// VaultGuard design tokens — Cinematic Dark + Glassmorphism, with a fully
// paired Light theme. Single source of truth for color, type, spacing, radius
// and motion. Every color resolves through `isDark`, so flipping `mode`
// re-themes the whole app reactively.
QtObject {
    id: theme

    // ---- Theme mode ----
    readonly property int modeSystem: 0
    readonly property int modeLight: 1
    readonly property int modeDark: 2
    property int mode: modeSystem

    // Follows the OS when in System mode (Qt 6.5+ colorScheme hint).
    readonly property bool isDark: mode === modeDark
        || (mode === modeSystem
            && Application.styleHints.colorScheme === Qt.ColorScheme.Dark)
    readonly property var modeLabels: ["System", "Light", "Dark"]

    // ---- Surfaces (deep slate dark / soft paper light) ----
    readonly property color bgDeep:     isDark ? "#070B14" : "#DBE2EC"
    readonly property color bgBase:     isDark ? "#0B1120" : "#E9EEF5"
    readonly property color bgElevated: isDark ? "#0F172A" : "#F6F8FC"
    readonly property color surface:      isDark ? Qt.rgba(1, 1, 1, 0.05)
                                                 : Qt.rgba(1, 1, 1, 0.55)
    readonly property color surfaceStrong: isDark ? Qt.rgba(1, 1, 1, 0.09)
                                                  : Qt.rgba(1, 1, 1, 0.85)

    // Frosted panel fill — more opaque than `surface` so ambient blobs read as a
    // soft tint, not murky bleed-through. The default fill for GlassCard.
    readonly property color glass:       isDark ? Qt.rgba(20 / 255, 28 / 255, 46 / 255, 0.62)
                                                : Qt.rgba(1, 1, 1, 0.72)
    readonly property color glassStrong: isDark ? Qt.rgba(24 / 255, 33 / 255, 54 / 255, 0.78)
                                                : Qt.rgba(1, 1, 1, 0.88)

    // ---- Brand ----
    readonly property color gold:       isDark ? "#F59E0B" : "#D97706"  // trust / primary
    readonly property color goldSoft:   isDark ? "#FBBF24" : "#F59E0B"
    readonly property color accent:     isDark ? "#8B5CF6" : "#7C3AED"  // tech accent
    readonly property color accentSoft: isDark ? "#A78BFA" : "#8B5CF6"

    // ---- Semantic ----
    readonly property color success:    isDark ? "#34D399" : "#059669"
    readonly property color warning:    isDark ? "#FBBF24" : "#D97706"
    readonly property color danger:     isDark ? "#F87171" : "#DC2626"
    readonly property color dangerDeep: isDark ? "#EF4444" : "#DC2626"

    // ---- Foreground ----
    readonly property color text:       isDark ? "#F8FAFC" : "#0F172A"
    readonly property color textMuted:  isDark ? "#94A3B8" : "#475569"
    readonly property color textFaint:  isDark ? "#64748B" : "#8A98AC"
    readonly property color textOnGold: "#1F1505"   // dark ink on gold, both modes

    // ---- Lines ----
    readonly property color border:       isDark ? Qt.rgba(1, 1, 1, 0.08)
                                                  : Qt.rgba(15 / 255, 23 / 255, 42 / 255, 0.10)
    readonly property color borderStrong: isDark ? Qt.rgba(1, 1, 1, 0.16)
                                                  : Qt.rgba(15 / 255, 23 / 255, 42 / 255, 0.18)

    // ---- Elevation + glow tints ----
    readonly property color shadow:    isDark ? Qt.rgba(0, 0, 0, 0.55)
                                              : Qt.rgba(15 / 255, 23 / 255, 42 / 255, 0.16)
    readonly property color goldGlow:   Qt.rgba(gold.r, gold.g, gold.b, isDark ? 0.35 : 0.28)
    readonly property color accentGlow: Qt.rgba(accent.r, accent.g, accent.b, isDark ? 0.30 : 0.22)

    // Glass sheen strength (top-edge highlight) differs per mode.
    readonly property color sheen: isDark ? Qt.rgba(1, 1, 1, 0.06) : Qt.rgba(1, 1, 1, 0.55)

    // ---- Typography ----
    readonly property string fontDisplay: "Orbitron"
    readonly property string fontBody:    "Exo 2"
    readonly property string fontMono:    "JetBrains Mono"

    readonly property int sizeDisplay: 34
    readonly property int sizeH1:      24
    readonly property int sizeH2:      18
    readonly property int sizeBody:    15
    readonly property int sizeSmall:   13
    readonly property int sizeMicro:   11

    // ---- Spacing scale (4 / 8 rhythm) ----
    readonly property int xs:  4
    readonly property int sm:  8
    readonly property int md:  16
    readonly property int lg:  24
    readonly property int xl:  32
    readonly property int xxl: 48

    // ---- Radius ----
    readonly property int radiusSm: 10
    readonly property int radius:   16
    readonly property int radiusLg: 22
    readonly property int radiusPill: 999

    // ---- Motion ----
    readonly property int durFast:  140
    readonly property int durBase:  220
    readonly property int durSlow:  340
}
