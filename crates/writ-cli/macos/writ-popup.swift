// writ-popup (M7.8): the approval popup on the Mac. A window over `writ sign --ui`: `writ`
// fetches each waiting ticket, checks it, builds the trusted display (as text and as sections
// of tagged rows, written by the same calls) and signs through ssh-keygen (Secretive's Touch
// ID); this only shows what `writ` sends, styled by each section's kind and each row's tag,
// and says which button was clicked. It never parses the text, decodes a ticket or signs
// (docs/architecture/clients.md#the-approval-popup-m78).
//
// Usage: writ-popup [--writ <path to writ>] [-- <more arguments for writ sign --ui>]
// By default the `writ` beside this program. Its environment is passed on (WRIT_HOME,
// WRIT_APPROVAL_URL, WRIT_APPROVAL_KEY, WRIT_APPROVAL_AGENT).
//
// The protocol: one JSON object per line each way. From `writ`: {"type": "show" | "queue" |
// "gone" | "done" | "failed" | "idle" | "status", …}. To `writ`: {"answer": "sign" | "refuse"
// | "skip" | "pick", "id": …, "feedback": …}.

import AppKit
import SwiftUI

/// The longest line read from `writ` (its display is bounded far below).
let maxLine = 8 * 1024 * 1024
/// How long both buttons stay disabled after a ticket shows: a click meant for another
/// window, a moment before this one came up, presses nothing.
let armDelay: UInt64 = 1_000_000_000
/// How long before `writ` is started again when it ends.
let restartDelay: TimeInterval = 3.0

// MARK: - What `writ` sends

/// One row of the structure: its label, its value (cleaned by `writ`), what it is.
struct DocRow: Decodable, Hashable {
    let label: String?
    let value: String
    let tag: String
}

/// One section of the structure.
struct DocSection: Decodable, Hashable {
    let kind: String
    let title: String
    let rows: [DocRow]
}

struct Doc: Decodable, Hashable {
    let sections: [DocSection]
}

/// A ticket of the list (the one shown among them).
struct Entry: Decodable, Hashable, Identifiable {
    let id: String
    let kind: String
    let title: String
    let repos: [String]
    let skipped: Bool
}

/// One line from `writ`; only the fields its type carries are set.
struct Event: Decodable {
    let type: String
    let id: String?
    let kind: String?
    let title: String?
    let repos: [String]?
    let expires_at: String?
    let display: String?
    let doc: Doc?
    let key: String?
    let waiting: [Entry]?
    let message: String?
}

/// The ticket on screen.
struct Shown: Equatable {
    let id: String
    let kind: String
    let title: String
    let repos: [String]
    let expires: Date?
    let display: String
    let doc: Doc
    let key: String
}

// MARK: - Running `writ sign --ui`

/// Runs `writ sign --ui` and hands each event it prints to `onEvent`, on the main thread.
@MainActor
final class Bridge {
    private let program: URL
    private let extra: [String]
    private var process: Process?
    private var input: FileHandle?
    private var pending = Data()
    private var stopping = false
    var onEvent: ((Event) -> Void)?
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
            // A line that isn't an event is dropped: nothing is shown from it.
            if let event = try? JSONDecoder().decode(Event.self, from: line) {
                onEvent?(event)
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

// MARK: - The window's state

/// A message at the bottom of the window.
struct Banner: Equatable {
    enum Kind { case success, failure, info }
    let kind: Kind
    let text: String
}

@MainActor
final class Model: ObservableObject {
    @Published var shown: Shown?
    @Published var waiting: [Entry] = []
    @Published var banner: Banner?
    /// The buttons work: false for a second after each ticket shows, and while a signature
    /// is asked.
    @Published var armed = false
    /// A signature or a refusal asked: the window waits for Touch ID.
    @Published var busy = false
    @Published var declining = false
    @Published var feedback = ""

    let bridge: Bridge
    var onVisible: ((Bool) -> Void)?
    private var arming: Task<Void, Never>?
    private var clearing: Task<Void, Never>?

    init(bridge: Bridge) {
        self.bridge = bridge
        bridge.onEvent = { [weak self] event in self?.handle(event) }
        bridge.onEnd = { [weak self] message in
            self?.say(Banner(kind: .failure, text: message))
        }
    }

    private static let dates: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    func handle(_ event: Event) {
        switch event.type {
        case "show": show(event)
        case "queue": waiting = event.waiting ?? []
        case "gone":
            if event.id == shown?.id { shown = nil }
        case "done":
            busy = false
            say(Banner(kind: .success, text: event.message ?? "Done."), clearAfter: 6)
        case "failed":
            busy = false
            // The ticket stays: `writ` sends it again, and the buttons come back then.
            say(Banner(kind: .failure, text: event.message ?? "Failed."))
        case "idle":
            shown = nil
            waiting = []
            busy = false
            declining = false
            onVisible?(false)
        case "status":
            say(Banner(kind: .info, text: event.message ?? ""))
        default: break
        }
    }

    private func show(_ event: Event) {
        guard let id = event.id, let doc = event.doc else { return }
        let fresh = id != shown?.id
        shown = Shown(
            id: id,
            kind: event.kind ?? "ticket",
            title: event.title ?? "",
            repos: event.repos ?? [],
            expires: event.expires_at.flatMap { Model.dates.date(from: $0) },
            display: event.display ?? "",
            doc: doc,
            key: event.key ?? ""
        )
        waiting = event.waiting ?? []
        busy = false
        if fresh {
            declining = false
            feedback = ""
            if banner?.kind == .failure { banner = nil }
        }
        arm()
        onVisible?(true)
    }

    /// Both buttons disabled, then enabled after `armDelay`.
    private func arm() {
        arming?.cancel()
        armed = false
        arming = Task { @MainActor in
            try? await Task.sleep(nanoseconds: armDelay)
            if !Task.isCancelled { self.armed = true }
        }
    }

    private func say(_ banner: Banner, clearAfter seconds: UInt64? = nil) {
        clearing?.cancel()
        self.banner = banner
        if let seconds {
            clearing = Task { @MainActor in
                try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
                if !Task.isCancelled, self.banner == banner { self.banner = nil }
            }
        }
    }

    // What a click says.

    func sign() {
        guard let id = shown?.id, armed, !busy else { return }
        busy = true
        say(Banner(kind: .info, text: "Signing: confirm with Touch ID…"))
        bridge.send(["answer": "sign", "id": id])
    }

    func refuse() {
        guard let id = shown?.id, armed, !busy else { return }
        busy = true
        say(Banner(kind: .info, text: "Refusing: confirm with Touch ID…"))
        bridge.send(["answer": "refuse", "id": id, "feedback": feedback])
    }

    func pick(_ id: String) {
        guard !busy, id != shown?.id else { return }
        bridge.send(["answer": "pick", "id": id])
    }

    /// The window closed: the ticket stays waiting, put aside by this run.
    func skip() {
        if let id = shown?.id { bridge.send(["answer": "skip", "id": id]) }
        shown = nil
        onVisible?(false)
    }
}

// MARK: - Styles

extension Color {
    static let agentTint = Color.orange
    static let addedTint = Color.green
    static let removedTint = Color.red
}

/// A kind of ticket as a small coloured capsule.
struct KindBadge: View {
    let kind: String

    var body: some View {
        Text(kind.uppercased())
            .font(.system(size: 9, weight: .bold))
            .tracking(0.6)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundStyle(color)
            .background(Capsule().fill(color.opacity(0.16)))
    }

    private var color: Color {
        switch kind {
        case "amendment": return .purple
        case "renewal": return .teal
        case "revision": return .blue
        default: return .accentColor
        }
    }
}

/// A repository's name as a chip.
struct Chip: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .medium, design: .monospaced))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 4).fill(Color.secondary.opacity(0.14)))
    }
}

/// A rounded card around a section.
struct Card<Content: View>: View {
    let tint: Color?
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(tint.map { $0.opacity(0.07) } ?? Color(nsColor: .controlBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder((tint ?? Color.secondary).opacity(tint == nil ? 0.18 : 0.45))
            )
    }
}

/// One row of a section, styled by its tag.
struct RowView: View {
    let row: DocRow

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            if let label = row.label {
                Text(label)
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
                    .frame(width: 150, alignment: .leading)
            }
            value
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder private var value: some View {
        switch row.tag {
        case "agent":
            quote(Color.agentTint)
        case "agent_added":
            quote(Color.addedTint, sign: "+")
        case "agent_removed":
            quote(Color.removedTint, sign: "−")
        case "added":
            mark(Color.addedTint, sign: "+")
        case "removed":
            mark(Color.removedTint, sign: "−")
        case "warning":
            Label {
                Text(row.value).font(.system(size: 12, design: .monospaced))
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.orange)
            .textSelection(.enabled)
        case "context":
            Text(row.value)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        default:
            Text(row.value)
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .textSelection(.enabled)
        }
    }

    /// The agent's words: behind a bar of their own colour, never mistaken for Writ's rows.
    private func quote(_ tint: Color, sign: String? = nil) -> some View {
        HStack(alignment: .top, spacing: 8) {
            RoundedRectangle(cornerRadius: 1.5).fill(tint).frame(width: 3)
            if let sign { Text(sign).font(.system(size: 12, weight: .bold)).foregroundStyle(tint) }
            Text(row.value)
                .font(.system(size: 12.5))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }

    /// A term's side of a change.
    private func mark(_ tint: Color, sign: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(sign).font(.system(size: 12, weight: .bold)).foregroundStyle(tint)
            Text(row.value)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(RoundedRectangle(cornerRadius: 4).fill(tint.opacity(0.12)))
    }
}

/// A section's rows, under a title.
struct SectionView: View {
    let section: DocSection
    let title: String
    let tint: Color?
    var icon: String? = nil

    var body: some View {
        Card(tint: tint) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    if let icon { Image(systemName: icon).foregroundStyle(tint ?? .secondary) }
                    Text(title).font(.system(size: 13, weight: .semibold))
                }
                ForEach(Array(section.rows.enumerated()), id: \.offset) { _, row in
                    RowView(row: row)
                }
            }
        }
    }
}

/// A section that folds, closed at first: the details below what is signed.
struct FoldedSection: View {
    let section: DocSection
    @State private var open = false

    var body: some View {
        Card(tint: nil) {
            DisclosureGroup(isExpanded: $open) {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(section.rows.enumerated()), id: \.offset) { _, row in
                        RowView(row: row)
                    }
                }
                .padding(.top, 8)
            } label: {
                Text(section.title).font(.system(size: 13, weight: .semibold))
            }
        }
    }
}

// MARK: - The window

struct Sidebar: View {
    @ObservedObject var model: Model

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(model.waiting.count == 1 ? "1 ticket waiting" : "\(model.waiting.count) tickets waiting")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(.secondary)
                .textCase(.uppercase)
                .padding(.horizontal, 14)
                .padding(.top, 14)
                .padding(.bottom, 8)
            ScrollView {
                VStack(spacing: 4) {
                    ForEach(model.waiting) { entry in
                        EntryRow(entry: entry, selected: entry.id == model.shown?.id)
                            .contentShape(Rectangle())
                            .onTapGesture { model.pick(entry.id) }
                    }
                }
                .padding(.horizontal, 8)
            }
        }
        .frame(width: 240)
        .background(Color(nsColor: .underPageBackgroundColor))
    }
}

struct EntryRow: View {
    let entry: Entry
    let selected: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                KindBadge(kind: entry.kind)
                Spacer()
                if entry.skipped {
                    Text("put aside").font(.system(size: 10)).foregroundStyle(.secondary)
                }
            }
            Text(entry.title)
                .font(.system(size: 13, weight: .medium))
                .lineLimit(2)
            Text(entry.repos.joined(separator: ", "))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(selected ? Color.accentColor.opacity(0.18) : Color.clear)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(selected ? Color.accentColor.opacity(0.6) : Color.clear)
        )
    }
}

struct Header: View {
    let shown: Shown

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                KindBadge(kind: shown.kind)
                Text(shown.id)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Spacer()
                Button("Copy as text") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(shown.display, forType: .string)
                }
                .buttonStyle(.link)
                .font(.system(size: 11))
                .focusable(false)
            }
            Text(shown.title)
                .font(.system(size: 20, weight: .semibold))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            HStack(spacing: 6) {
                ForEach(shown.repos, id: \.self) { Chip(text: $0) }
                if let expires = shown.expires {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text(left(until: expires, now: context.date))
                            .font(.system(size: 12))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func left(until: Date, now: Date) -> String {
        let seconds = Int(until.timeIntervalSince(now))
        if seconds <= 0 { return "expired" }
        let h = seconds / 3600, m = (seconds % 3600) / 60, s = seconds % 60
        return h > 0 ? "expires in \(h)h\(String(format: "%02d", m))m" : "expires in \(m)m\(String(format: "%02d", s))s"
    }
}

struct Detail: View {
    @ObservedObject var model: Model
    let shown: Shown

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Header(shown: shown)
                    ForEach(sections(["signing"]), id: \.self) {
                        SectionView(section: $0, title: "You are signing", tint: .accentColor, icon: "signature")
                    }
                    ForEach(sections(["changes"]), id: \.self) {
                        SectionView(section: $0, title: $0.title, tint: .purple, icon: "arrow.left.arrow.right")
                    }
                    ForEach(sections(["agent"]), id: \.self) {
                        SectionView(
                            section: $0, title: "Written by the agent: untrusted, never acted on",
                            tint: .agentTint, icon: "exclamationmark.bubble")
                    }
                    ForEach(sections(["feedback", "renewal"]), id: \.self) {
                        SectionView(section: $0, title: $0.title, tint: nil)
                    }
                    ForEach(sections(["others"]), id: \.self) { section in
                        let warn = section.rows.contains { $0.tag == "warning" }
                        SectionView(section: section, title: section.title, tint: warn ? .orange : nil)
                    }
                    ForEach(sections(["ticket", "who", "lease", "repository"]), id: \.self) {
                        FoldedSection(section: $0)
                    }
                }
                .padding(20)
            }
            Divider()
            Footer(model: model, shown: shown)
        }
    }

    private func sections(_ kinds: [String]) -> [DocSection] {
        shown.doc.sections.filter { kinds.contains($0.kind) }
    }
}

struct Footer: View {
    @ObservedObject var model: Model
    let shown: Shown

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let banner = model.banner {
                HStack(spacing: 8) {
                    switch banner.kind {
                    case .info:
                        if model.busy { ProgressView().controlSize(.small) } else {
                            Image(systemName: "info.circle").foregroundStyle(.secondary)
                        }
                    case .success: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    case .failure: Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
                    }
                    Text(banner.text).font(.system(size: 12)).textSelection(.enabled)
                }
            }
            if model.declining {
                HStack(spacing: 8) {
                    TextField("Feedback for the agent (optional)", text: $model.feedback)
                        .textFieldStyle(.roundedBorder)
                    Button("Back") { model.declining = false }
                        .focusable(false)
                        .disabled(model.busy)
                    Button("Refuse") { model.refuse() }
                        .focusable(false)
                        .tint(.red)
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.armed || model.busy)
                }
            } else {
                HStack(spacing: 10) {
                    Label(shown.key, systemImage: "key")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("Decline…") { model.declining = true }
                        .focusable(false)
                        .controlSize(.large)
                        .disabled(!model.armed || model.busy)
                    Button("Sign") { model.sign() }
                        .focusable(false)
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.armed || model.busy)
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
        .background(.bar)
    }
}

struct Root: View {
    @ObservedObject var model: Model

    var body: some View {
        HStack(spacing: 0) {
            Sidebar(model: model)
            Divider()
            if let shown = model.shown {
                Detail(model: model, shown: shown)
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.seal").font(.system(size: 30)).foregroundStyle(.secondary)
                    Text("Nothing waits for you.").foregroundStyle(.secondary)
                    if let banner = model.banner { Text(banner.text).font(.system(size: 12)) }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 780, minHeight: 520)
    }
}

// MARK: - The panel

/// The panel the window lives in: above every app's windows, on every space, full-screen
/// ones too (as Touch ID's prompt comes up), below the system's own prompts.
@MainActor
final class Popup: NSObject, NSWindowDelegate {
    private let panel: NSPanel
    private let model: Model

    init(model: Model) {
        self.model = model
        panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 1000, height: 720),
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
            backing: .buffered, defer: false)
        super.init()
        panel.title = "Writ: waiting for your signature"
        panel.titlebarAppearsTransparent = true
        panel.level = .modalPanel
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .stationary]
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.delegate = self
        panel.contentView = NSHostingView(rootView: Root(model: model))
        model.onVisible = { [weak self] visible in self?.setVisible(visible) }
    }

    private func setVisible(_ visible: Bool) {
        if !visible {
            panel.orderOut(nil)
            return
        }
        if !panel.isVisible { panel.center() }
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        panel.orderFrontRegardless()
    }

    /// The window closed: the ticket stays waiting, put aside by this run (`writ sign` in a
    /// terminal still reaches it).
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        model.skip()
        return false
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private let bridge: Bridge
    private var model: Model?
    private var popup: Popup?

    init(bridge: Bridge) {
        self.bridge = bridge
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let model = Model(bridge: bridge)
        self.model = model
        popup = Popup(model: model)
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
