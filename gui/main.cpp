// VaultGuard GUI entry point.
//
// Loads the QML "VaultGuard" module. The UI talks to a mock `VaultController`
// singleton written in QML so it runs without the crypto backend. To wire the
// real core, expose a C++ QObject (qmlRegisterSingletonInstance) implementing
// the same property/signal surface and point the screens at it.

#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickStyle>

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);

    app.setApplicationName("VaultGuard");
    app.setOrganizationName("VaultGuard");
    app.setApplicationDisplayName("VaultGuard");

    // Basic style is required so our custom Controls templates apply cleanly.
    QQuickStyle::setStyle("Basic");

    QQmlApplicationEngine engine;
    QObject::connect(
        &engine, &QQmlApplicationEngine::objectCreationFailed,
        &app, []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);

    engine.loadFromModule("VaultGuard", "Main");
    if (engine.rootObjects().isEmpty())
        return -1;

    return app.exec();
}
