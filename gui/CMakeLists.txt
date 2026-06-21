cmake_minimum_required(VERSION 3.21)

project(VaultGuardGui VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Quick QuickControls2)

qt_standard_project_setup(REQUIRES 6.5)

# QML lives in the qml/ subdirectory; opt into the modern per-directory handling.
if(QT_KNOWN_POLICY_QTP0004)
    qt_policy(SET QTP0004 NEW)
endif()

# Mark the QML-defined singletons BEFORE qt_add_qml_module so the generated
# qmldir emits the `singleton` keyword for them.
set_source_files_properties(qml/Theme.qml qml/VaultController.qml PROPERTIES
    QT_QML_SINGLETON_TYPE TRUE
)

qt_add_executable(vaultguard_gui
    main.cpp
)

qt_add_qml_module(vaultguard_gui
    URI VaultGuard
    VERSION 1.0
    QML_FILES
        qml/Main.qml
        qml/Theme.qml
        qml/VaultController.qml
        qml/AmbientBackground.qml
        qml/GlassCard.qml
        qml/GhostButton.qml
        qml/GroupLabel.qml
        qml/Icon.qml
        qml/NavRail.qml
        qml/Pill.qml
        qml/PasswordField.qml
        qml/PasswordStrength.qml
        qml/PrimaryButton.qml
        qml/SecretRevealDialog.qml
        qml/SecretRow.qml
        qml/ShieldGlyph.qml
        qml/ThemeToggle.qml
        qml/Toast.qml
        qml/VaultTextField.qml
        qml/DashboardScreen.qml
        qml/PrepareScreen.qml
        qml/RecoverScreen.qml
        qml/StoreWalletScreen.qml
        qml/UnlockScreen.qml
    RESOURCES
        fonts/Orbitron.ttf
        fonts/Exo2.ttf
        fonts/JetBrainsMono.ttf
)

target_link_libraries(vaultguard_gui PRIVATE
    Qt6::Quick
    Qt6::QuickControls2
)
