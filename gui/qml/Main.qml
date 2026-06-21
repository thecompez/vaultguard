import QtQuick
import QtQuick.Controls.Basic
import QtQuick.Window
import VaultGuard

ApplicationWindow {
    id: app
    width: 1180
    height: 760
    minimumWidth: 920
    minimumHeight: 640
    visible: true
    title: "VaultGuard"
    color: Theme.bgBase
    Behavior on color { ColorAnimation { duration: Theme.durSlow } }

    // Bundled typography — registers the "Orbitron", "Exo 2" and "JetBrains
    // Mono" families the theme references, so the app looks identical on any OS.
    FontLoader { source: "qrc:/qt/qml/VaultGuard/fonts/Orbitron.ttf" }
    FontLoader { source: "qrc:/qt/qml/VaultGuard/fonts/Exo2.ttf" }
    FontLoader { source: "qrc:/qt/qml/VaultGuard/fonts/JetBrainsMono.ttf" }

    // Respect the OS reduced-motion preference for ambient animation.
    property bool reduceMotion: false

    AmbientBackground {
        anchors.fill: parent
        animated: !app.reduceMotion
    }

    // Appearance toggle for the locked screens (the nav rail carries it once
    // unlocked). Floats top-right above the gate.
    ThemeToggle {
        anchors { top: parent.top; right: parent.right; margins: Theme.lg }
        visible: !VaultController.unlocked
        z: 50
    }

    // ---- Locked vs unlocked flow ----
    // 0 = Unlock, 1 = Prepare USB (pre-unlock), then the unlocked workspace.
    StackView {
        id: gate
        anchors.fill: parent
        visible: !VaultController.unlocked
        initialItem: unlockComp

        pushEnter: Transition {
            ParallelAnimation {
                NumberAnimation { property: "opacity"; from: 0; to: 1; duration: Theme.durBase }
                NumberAnimation { property: "y"; from: 24; to: 0
                    duration: Theme.durSlow; easing.type: Easing.OutCubic }
            }
        }
        popEnter: Transition {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: Theme.durBase }
        }

        Component {
            id: unlockComp
            UnlockScreen {
                onUnlocked: { /* binding on VaultController.unlocked swaps views */ }
                onPrepareRequested: gate.push(prepareComp)
                onToast: (kind, message) => toastHost.show(kind, message)
            }
        }
        Component {
            id: prepareComp
            PrepareScreen {
                onCancelled: gate.pop()
                onDone: { /* unlocked binding swaps views */ }
                onToast: (kind, message) => toastHost.show(kind, message)
            }
        }
    }

    // ---- Unlocked workspace ----
    Row {
        anchors.fill: parent
        visible: VaultController.unlocked

        NavRail {
            id: rail
            height: parent.height
            current: 0
            onNavigate: (i) => { rail.current = i; workspace.replace(pageFor(i)) }
            onLockRequested: { VaultController.lock(); rail.current = 0 }
        }

        StackView {
            id: workspace
            width: parent.width - rail.width
            height: parent.height
            initialItem: dashComp

            replaceEnter: Transition {
                ParallelAnimation {
                    NumberAnimation { property: "opacity"; from: 0; to: 1; duration: Theme.durBase }
                    NumberAnimation { property: "x"; from: 18; to: 0
                        duration: Theme.durSlow; easing.type: Easing.OutCubic }
                }
            }
            replaceExit: Transition {
                NumberAnimation { property: "opacity"; from: 1; to: 0; duration: Theme.durFast }
            }
        }
    }

    // Reset the workspace whenever we (re)enter the unlocked state.
    Connections {
        target: VaultController
        function onUnlockedChanged() {
            if (VaultController.unlocked) {
                rail.current = 0
                workspace.replace(dashComp)
            } else {
                gate.clear()
                gate.push(unlockComp)
            }
        }
        function onNotify(kind, message) { toastHost.show(kind, message) }
    }

    function pageFor(i) {
        return i === 1 ? storeComp : i === 2 ? recoverComp : dashComp
    }

    // ---- Page components ----
    Component {
        id: dashComp
        DashboardScreen {
            onStoreRequested: { rail.current = 1; workspace.replace(storeComp) }
            onRecoverRequested: (id) => {
                rail.current = 2
                workspace.replace(recoverComp, { preselect: id })
            }
        }
    }
    Component {
        id: storeComp
        StoreWalletScreen {
            onCancelled: { rail.current = 0; workspace.replace(dashComp) }
            onDone: { rail.current = 0; workspace.replace(dashComp) }
            onToast: (kind, message) => toastHost.show(kind, message)
        }
    }
    Component {
        id: recoverComp
        RecoverScreen {
            onRevealReady: (secret) => reveal.open(secret)
            onToast: (kind, message) => toastHost.show(kind, message)
        }
    }

    // ---- Overlays ----
    SecretRevealDialog {
        id: reveal
        onExportRequested: (id) => VaultController.exportPlaintext(id)
        onToast: (kind, message) => toastHost.show(kind, message)
    }

    Toast { id: toastHost }
}
