import AppKit
@main
struct Host {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        app.run()
    }
}
