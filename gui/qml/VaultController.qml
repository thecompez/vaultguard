pragma Singleton
import QtQuick

// Mock controller that lets the UI run standalone (no crypto backend).
// Replace the function bodies with calls into the real VaultGuard C++ core
// (expose a QObject as `vault` and forward to it). The signal/property
// surface below is the contract the QML screens depend on.
QtObject {
    id: vault

    // ---- Vault / device state ----
    property bool   deviceDetected: true               // a VaultGuard USB is present
    property string deviceName: "VAULT-PRO"
    property string deviceSize: "64.0 GB"
    property string mountPath: "/Volumes/VAULT-PRO"
    property bool   unlocked: false
    property bool   busy: false

    // ---- Wallet index (decrypted in memory only after unlock) ----
    property var wallets: []

    // Emitted on any user-facing outcome so screens can raise a toast.
    signal notify(string kind, string message)   // kind: "ok" | "error" | "warn"
    signal unlockResult(bool ok)
    signal walletStored(string id)
    signal secretRevealed(var secret)            // { id, name, privateKey, seedPhrase }

    // ---- Seed data for preview ----
    function _seed() {
        wallets = [
            { id: "cold-01",  name: "Cold Storage",   currency: "BTC", createdAt: "2026-02-14" },
            { id: "eth-main",  name: "ETH Treasury",  currency: "ETH", createdAt: "2026-03-02" },
            { id: "ledger-x",  name: "Ledger Backup",  currency: "SOL", createdAt: "2026-05-21" }
        ]
    }

    // ---- Actions (mocked with realistic latency) ----
    function unlock(password) {
        busy = true
        _delay(700, function () {
            busy = false
            const ok = password && password.length >= 4
            if (ok) {
                _seed()
                unlocked = true
                notify("ok", "Vault unlocked — " + wallets.length + " wallets loaded.")
            } else {
                notify("error", "Incorrect password. Try again.")
            }
            unlockResult(ok)
        })
    }

    function lock() {
        unlocked = false
        wallets = []
    }

    function prepareUsb(driveName, password) {
        busy = true
        _delay(1100, function () {
            busy = false
            deviceDetected = true
            deviceName = driveName
            unlocked = true
            wallets = []
            notify("ok", "USB “" + driveName + "” formatted and vault initialized.")
        })
    }

    function storeWallet(w) {
        busy = true
        _delay(900, function () {
            busy = false
            var list = wallets.slice()
            list.push({
                id: w.id, name: w.name, currency: w.currency,
                createdAt: Qt.formatDate(new Date(), "yyyy-MM-dd")
            })
            wallets = list
            notify("ok", "Wallet “" + w.id + "” sealed into the vault.")
            walletStored(w.id)
        })
    }

    // One-time reveal — backend decrypts, returns once, never persists plaintext.
    function reveal(walletId, password) {
        busy = true
        _delay(650, function () {
            busy = false
            secretRevealed({
                id: walletId,
                name: (wallets.find(function (x) { return x.id === walletId }) || {}).name || walletId,
                privateKey: "L4mE0nLy" + walletId.toUpperCase().replace(/-/g, "") + "DemoPrivKeyDoNotUse",
                seedPhrase: "ribbon clutch slogan canyon vivid orphan tonic ladder static "
                            + "harbor velvet pioneer"
            })
        })
    }

    function exportPlaintext(walletId) {
        notify("warn", "Plaintext export written to vault — delete it as soon as possible.")
    }

    function generatePassword() {
        const set = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%*-_"
        var out = ""
        for (var i = 0; i < 24; i++)
            out += set.charAt(Math.floor(Math.random() * set.length))
        return out
    }

    // Lightweight async helper.
    property var _cb: null
    property Timer _timer: Timer {
        repeat: false
        onTriggered: if (vault._cb) vault._cb()
    }
    function _delay(ms, cb) {
        _cb = cb
        _timer.interval = ms
        _timer.restart()
    }
}
