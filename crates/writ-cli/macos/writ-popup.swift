// writ-popup (M7.8): the approval popup on the Mac. A thin window over `writ sign --ui`: `writ`
// fetches each waiting ticket, checks it, builds the trusted display and signs through
// ssh-keygen (Secretive's Touch ID); this only shows the text `writ` sends and says which
// button was clicked. Nothing here decides, decodes a ticket or signs
// (docs/architecture/clients.md#the-approval-popup-m78).
//
// Usage: writ-popup [--writ <path to writ>] [-- <more arguments for writ sign --ui>]
// By default the `writ` beside this program. Its environment is passed on (WRIT_HOME,
// WRIT_APPROVAL_URL, WRIT_APPROVAL_KEY, WRIT_APPROVAL_AGENT).
//
// The protocol: one JSON object per line each way. From `writ`: {"type": "show" | "queue" |
// "gone" | "done" | "failed" | "idle" | "status", …}. To `writ`: {"answer": "sign" | "refuse"
// | "skip", "id": …, "feedback": …}.

import AppKit

/// The longest line read from `writ` (its display is bounded far below).
let maxLine = 8 * 1024 * 1024
/// How long both buttons stay disabled after a ticket shows: a click meant for another
/// window, a moment before this one came up, presses nothing.
let armDelay: TimeInterval = 1.0
/// How long before `writ` is started again when it ends.
let restartDelay: TimeInterval = 3.0
/// The most tickets listed behind the one shown (the rest are counted).
let maxListed = 5

/// A ticket waiting behind the one shown, as `writ` names it.
struct Waiting {
    let id: String
    let title: String
    let repos: [String]
    let skipped: Bool

    init?(_ value: Any) {
        guard let object = value as? [String: Any],
            let id = object["id"] as? String,
            let title = object["title"] as? String
        else { return nil }
        self.id = id
        self.title = title
        self.repos = (object["repos"] as? [String]) ?? []
        self.skipped = (object["skipped"] as? Bool) ?? false
    }
}

/// Runs `writ sign --ui` and hands each line it prints to `onLine`, on the main thread.
@MainActor
final class Bridge {
    private let program: URL
    private let extra: [String]
    private var process: Process?
    private var input: FileHandle?
    private var pending = Data()
    private var stopping = false
    var onLine: (([String: Any]) -> Void)?
    var onEnd: ((String) -> Void)?

    init(program: URL, extra: [String]) {
        self.program = program
        self.extra = extra
    }

    func start() {
        let process = Process()
        process.executableURL = program
        process.arguments = ["sign", "--ui"] + extra
        let stdin = Pipe()
        let stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        // Its errors (ssh-keygen's, on a failed signature) to this program's log.
        process.standardError = FileHandle.standardError
        stdout.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            DispatchQueue.main.async {
                MainActor.assumeIsolated { self.received(data) }
            }
        }
        process.terminationHandler = { ended in
            let status = ended.terminationStatus
            DispatchQueue.main.async {
                MainActor.assumeIsolated { self.ended(status) }
            }
        }
        do {
            try process.run()
        } catch {
            onEnd?("cannot start \(program.path): \(error.localizedDescription)")
            scheduleRestart()
            return
        }
        self.process = process
        self.input = stdin.fileHandleForWriting
        pending = Data()
    }

    func stop() {
        stopping = true
        try? input?.close()
        process?.terminate()
    }

    /// Sends one answer, a line of JSON.
    func send(_ answer: [String: String]) {
        guard let input,
            var line = try? JSONSerialization.data(withJSONObject: answer, options: [.sortedKeys])
        else { return }
        line.append(0x0A)
        try? input.write(contentsOf: line)
    }

    private func received(_ data: Data) {
        if data.isEmpty { return }
        pending.append(data)
        while let end = pending.firstIndex(of: 0x0A) {
            let line = pending[pending.startIndex..<end]
            pending.removeSubrange(pending.startIndex...end)
            if let object = try? JSONSerialization.jsonObject(with: line) as? [String: Any] {
                onLine?(object)
            }
        }
        if pending.count > maxLine {
            // A line past any display `writ` makes: not ours to read. Started again.
            onEnd?("writ sent a line longer than \(maxLine) bytes")
            process?.terminate()
        }
    }

    private func ended(_ status: Int32) {
        process = nil
        input = nil
        if stopping { return }
        onEnd?("writ sign --ui ended (status \(status)): started again in \(Int(restartDelay)) s")
        scheduleRestart()
    }

    private func scheduleRestart() {
        DispatchQueue.main.asyncAfter(deadline: .now() + restartDelay) {
            MainActor.assumeIsolated {
                if !self.stopping && self.process == nil { self.start() }
            }
        }
    }
}

/// A button that never takes the keyboard's focus: no key typed into this window, or into
/// another app while this one came up, can press it (Return, Space).
final class ClickOnlyButton: NSButton {
    override var acceptsFirstResponder: Bool { false }
}

/// The window: the ticket's display, what waits behind it, Sign and Decline.
@MainActor
final class Popup: NSObject, NSWindowDelegate {
    private let bridge: Bridge
    private let panel: NSPanel
    private let heading = NSTextField(labelWithString: "")
    private let queue = NSTextField(wrappingLabelWithString: "")
    private let text = NSTextView()
    private let key = NSTextField(labelWithString: "")
    private let status = NSTextField(wrappingLabelWithString: "")
    private let sign = ClickOnlyButton(title: "Sign", target: nil, action: nil)
    private let decline = ClickOnlyButton(title: "Decline…", target: nil, action: nil)
    private let feedbackRow = NSStackView()
    private let feedback = NSTextField()
    private let back = ClickOnlyButton(title: "Back", target: nil, action: nil)
    private let refuse = ClickOnlyButton(title: "Refuse", target: nil, action: nil)
    private var shownID: String?
    private var arming: DispatchWorkItem?

    init(bridge: Bridge) {
        self.bridge = bridge
        panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 760, height: 640),
            styleMask: [.titled, .closable, .resizable, .utilityWindow],
            backing: .buffered, defer: false)
        super.init()
        panel.title = "Writ: a ticket waits for your signature"
        // Above every app's windows, on every space, full-screen ones too (as Touch ID's
        // prompt comes up), and below the system's own prompts.
        panel.level = .modalPanel
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.delegate = self
        panel.minSize = NSSize(width: 520, height: 360)
        build()
        bridge.onLine = { [weak self] line in self?.handle(line) }
        bridge.onEnd = { [weak self] message in self?.say(message, failure: true) }
    }

    private func build() {
        heading.font = .boldSystemFont(ofSize: 15)
        heading.lineBreakMode = .byTruncatingTail
        queue.font = .systemFont(ofSize: 12)
        queue.textColor = .secondaryLabelColor

        text.isEditable = false
        text.isSelectable = true
        text.isRichText = false
        text.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        text.textContainerInset = NSSize(width: 6, height: 6)
        text.isVerticallyResizable = true
        text.isHorizontallyResizable = true
        text.textContainer?.widthTracksTextView = false
        text.textContainer?.containerSize = NSSize(
            width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
        text.autoresizingMask = [.width]
        let scroll = NSScrollView()
        scroll.documentView = text
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.borderType = .bezelBorder
        scroll.translatesAutoresizingMaskIntoConstraints = false

        key.font = .systemFont(ofSize: 11)
        key.textColor = .secondaryLabelColor
        key.lineBreakMode = .byTruncatingMiddle
        status.font = .systemFont(ofSize: 12)

        for (button, action) in [
            (sign, #selector(signClicked)), (decline, #selector(declineClicked)),
            (back, #selector(backClicked)), (refuse, #selector(refuseClicked)),
        ] {
            button.target = self
            button.action = action
            button.bezelStyle = .rounded
            // No default button: Return presses nothing.
            button.keyEquivalent = ""
        }
        feedback.placeholderString = "Feedback for the agent (optional)"
        feedback.font = .systemFont(ofSize: 12)
        feedbackRow.orientation = .horizontal
        feedbackRow.spacing = 8
        for view in [feedback, back, refuse] { feedbackRow.addArrangedSubview(view) }
        feedbackRow.isHidden = true

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let buttons = NSStackView(views: [key, spacer, decline, sign])
        buttons.orientation = .horizontal
        buttons.spacing = 8

        let column = NSStackView(views: [heading, queue, scroll, status, feedbackRow, buttons])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 8
        column.edgeInsets = NSEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        column.translatesAutoresizingMaskIntoConstraints = false
        let content = NSView()
        content.addSubview(column)
        panel.contentView = content
        NSLayoutConstraint.activate([
            column.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            column.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            column.topAnchor.constraint(equalTo: content.topAnchor),
            column.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            scroll.widthAnchor.constraint(equalTo: column.widthAnchor, constant: -24),
            buttons.widthAnchor.constraint(equalTo: column.widthAnchor, constant: -24),
            feedbackRow.widthAnchor.constraint(equalTo: column.widthAnchor, constant: -24),
            scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 200),
        ])
    }

    // MARK: what `writ` says

    private func handle(_ line: [String: Any]) {
        switch line["type"] as? String {
        case "show": show(line)
        case "queue": setQueue(line["waiting"])
        case "gone":
            if (line["id"] as? String) == shownID { hide() }
        case "done":
            say((line["message"] as? String) ?? "Done.", failure: false)
        case "failed":
            say((line["message"] as? String) ?? "Failed.", failure: true)
            // The ticket stays shown: `writ` sends it again, and the buttons come back then.
        case "idle": hide()
        case "status": say((line["message"] as? String) ?? "", failure: true)
        default: break
        }
    }

    private func show(_ line: [String: Any]) {
        guard let id = line["id"] as? String, let display = line["display"] as? String else {
            return
        }
        let kind = (line["kind"] as? String) ?? "ticket"
        let title = (line["title"] as? String) ?? ""
        let fresh = id != shownID
        shownID = id
        heading.stringValue = "\(kind.capitalized) \(id): \(title)"
        text.string = display
        if fresh { text.scrollToBeginningOfDocument(nil) }
        key.stringValue = "Approval key: \((line["key"] as? String) ?? "")"
        if fresh { status.stringValue = "" }
        setQueue(line["waiting"])
        showDecisionButtons()
        arm()
        if !panel.isVisible { panel.center() }
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        panel.orderFrontRegardless()
    }

    /// The tickets waiting behind the one shown, newest last.
    private func setQueue(_ value: Any?) {
        let waiting = ((value as? [Any]) ?? []).compactMap(Waiting.init)
        if waiting.isEmpty {
            queue.stringValue = "Nothing else waits."
            panel.title = "Writ: a ticket waits for your signature"
            return
        }
        panel.title = "Writ: \(waiting.count + 1) tickets wait for your signature"
        var lines = ["\(waiting.count) more waiting behind this one (newest last):"]
        for item in waiting.prefix(maxListed) {
            let repos = item.repos.isEmpty ? "" : " [\(item.repos.joined(separator: ", "))]"
            let aside = item.skipped ? " (put aside)" : ""
            lines.append("  • \(item.id): \(item.title)\(repos)\(aside)")
        }
        if waiting.count > maxListed {
            lines.append("  … and \(waiting.count - maxListed) more")
        }
        queue.stringValue = lines.joined(separator: "\n")
    }

    private func say(_ message: String, failure: Bool) {
        status.stringValue = message
        status.textColor = failure ? .systemRed : .secondaryLabelColor
    }

    private func hide() {
        shownID = nil
        arming?.cancel()
        panel.orderOut(nil)
    }

    // MARK: the buttons

    /// Both buttons disabled, then enabled after [armDelay]: a click aimed at another window
    /// as this one came up presses nothing.
    private func arm() {
        arming?.cancel()
        for button in [sign, decline, refuse] { button.isEnabled = false }
        let item = DispatchWorkItem { [weak self] in
            MainActor.assumeIsolated {
                guard let self else { return }
                for button in [self.sign, self.decline, self.refuse] { button.isEnabled = true }
            }
        }
        arming = item
        DispatchQueue.main.asyncAfter(deadline: .now() + armDelay, execute: item)
    }

    private func showDecisionButtons() {
        feedbackRow.isHidden = true
        feedback.stringValue = ""
        sign.isHidden = false
        decline.isHidden = false
    }

    private func waitingForSignature(_ message: String) {
        arming?.cancel()
        for button in [sign, decline, back, refuse] { button.isEnabled = false }
        say(message, failure: false)
    }

    @objc private func signClicked() {
        guard let id = shownID else { return }
        waitingForSignature("Signing: confirm with Touch ID…")
        bridge.send(["answer": "sign", "id": id])
    }

    @objc private func declineClicked() {
        sign.isHidden = true
        decline.isHidden = true
        feedbackRow.isHidden = false
        back.isEnabled = true
        panel.makeFirstResponder(feedback)
    }

    @objc private func backClicked() {
        showDecisionButtons()
    }

    @objc private func refuseClicked() {
        guard let id = shownID else { return }
        waitingForSignature("Refusing: confirm with Touch ID…")
        bridge.send(["answer": "refuse", "id": id, "feedback": feedback.stringValue])
    }

    /// The window closed: the ticket stays waiting, put aside by this run (`writ sign` in a
    /// terminal still reaches it).
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        if let id = shownID { bridge.send(["answer": "skip", "id": id]) }
        hide()
        return false
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let bridge: Bridge
    private var popup: Popup?

    init(bridge: Bridge) {
        self.bridge = bridge
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        popup = Popup(bridge: bridge)
        bridge.start()
    }

    func applicationWillTerminate(_ notification: Notification) {
        bridge.stop()
    }
}

/// `--writ <path>`, then what follows `--`; anything else is refused.
func arguments() -> (URL, [String]) {
    var args = Array(CommandLine.arguments.dropFirst())
    let beside = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        .deletingLastPathComponent().appendingPathComponent("writ")
    var program = beside
    var extra: [String] = []
    while let first = args.first {
        args.removeFirst()
        switch first {
        case "--writ":
            guard let path = args.first else { usage() }
            args.removeFirst()
            program = URL(fileURLWithPath: path)
        case "--":
            extra = args
            args = []
        default: usage()
        }
    }
    return (program, extra)
}

func usage() -> Never {
    FileHandle.standardError.write(
        Data("usage: writ-popup [--writ <path to writ>] [-- <arguments for writ sign --ui>]\n".utf8))
    exit(2)
}

MainActor.assumeIsolated {
    let (program, extra) = arguments()
    let app = NSApplication.shared
    // An accessory: no Dock icon, no menu bar, a window only when a ticket waits.
    app.setActivationPolicy(.accessory)
    let delegate = AppDelegate(bridge: Bridge(program: program, extra: extra))
    app.delegate = delegate
    app.run()
}
