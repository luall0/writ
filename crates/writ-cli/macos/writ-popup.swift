// writ-popup (M7.8, redesigned in M7.9.5): the approval popup on the Mac. A window over `writ sign --ui`: `writ`
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
// "gone" | "done" | "failed" | "idle" | "status" | "reached", …}. To `writ`: {"answer": "sign"
// | "refuse" | "skip" | "pick", "id": …, "feedback": …}.

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

/// One row of the structure: its label, its value (cleaned by `writ`), what it is, and for a
/// list-valued term its items (`writ` splits them: the app never splits a value).
struct DocRow: Decodable, Hashable {
    let label: String?
    let value: String
    let tag: String
    let items: [String]?
    /// The time the row shows (RFC 3339): the window says how far it is.
    let at: String?
    /// For the expected paths: the same items as a tree, built by `writ`.
    let tree: [TreeNode]?
    /// A change to a per-repository term over several repositories: its repository.
    let repo: String?
}

/// One node of a path tree: a folder (its name ends with `/`) or a leaf (`file`, `pattern`,
/// `everything`). Every path is the names on its way down: the app never splits one.
struct TreeNode: Decodable, Hashable {
    let name: String
    let kind: String
    let paths: Int
    let children: [TreeNode]?
}

/// One section of the structure.
struct DocSection: Decodable, Hashable {
    let kind: String
    let title: String
    /// A repository's section: its name.
    let repo: String?
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
    /// The last `status` banner: dropped when the daemon is reached again.
    private var status: Banner?

    init(bridge: Bridge) {
        self.bridge = bridge
        bridge.onEvent = { [weak self] event in self?.handle(event) }
        bridge.onEnd = { [weak self] message in
            self?.say(Banner(kind: .failure, text: message))
        }
    }

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
            let lost = Banner(kind: .info, text: event.message ?? "")
            status = lost
            say(lost)
        case "reached":
            // The daemon answers again: the message that said it couldn't goes (another
            // shown since stays).
            if let status, banner == status { banner = nil }
            status = nil
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
            expires: Times.date(event.expires_at),
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
        say(Banner(kind: .info, text: "Signing: confirm in your ssh-agent…"))
        bridge.send(["answer": "sign", "id": id])
    }

    func refuse() {
        guard let id = shown?.id, armed, !busy else { return }
        busy = true
        say(Banner(kind: .info, text: "Refusing: confirm in your ssh-agent…"))
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
    static let changeTint = Color.purple
}

/// The tags of the agent's words: their rows go to the right pane, never among Writ's.
let agentTags: Set<String> = ["agent", "agent_added", "agent_removed"]

/// Times as people read them: how far ("in 2h", "3 min ago") and the clock time beside it.
@MainActor
enum Times {
    static let iso: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()
    private static let clockFormat: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .none
        f.timeStyle = .short
        return f
    }()
    private static let dayFormat: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

    static func date(_ text: String?) -> Date? { text.flatMap { iso.date(from: $0) } }

    static func relative(_ date: Date, now: Date) -> String {
        let seconds = Int(date.timeIntervalSince(now))
        let span = abs(seconds)
        let text: String
        if span < 60 {
            text = "\(span) s"
        } else if span < 3600 {
            text = "\(span / 60) min"
        } else if span < 86_400 {
            let h = span / 3600, m = (span % 3600) / 60
            text = m == 0 ? "\(h)h" : "\(h)h \(String(format: "%02d", m))m"
        } else {
            let d = span / 86_400, h = (span % 86_400) / 3600
            text = h == 0 ? "\(d)d" : "\(d)d \(h)h"
        }
        return seconds < 0 ? "\(text) ago" : "in \(text)"
    }

    static func clock(_ date: Date, now: Date) -> String {
        let calendar = Calendar.current
        if calendar.isDate(date, inSameDayAs: now) { return "today at \(clockFormat.string(from: date))" }
        if calendar.isDateInTomorrow(date) { return "tomorrow at \(clockFormat.string(from: date))" }
        if calendar.isDateInYesterday(date) { return "yesterday at \(clockFormat.string(from: date))" }
        return dayFormat.string(from: date)
    }
}

/// A kind of ticket as a small coloured capsule.
struct KindBadge: View {
    let kind: String
    var long = false

    var body: some View {
        Text(text)
            .font(.system(size: long ? 11 : 9, weight: .bold))
            .tracking(0.5)
            .padding(.horizontal, long ? 8 : 6)
            .padding(.vertical, 2)
            .foregroundStyle(color)
            .background(RoundedRectangle(cornerRadius: 5).fill(color.opacity(0.16)))
    }

    private var text: String {
        switch kind {
        case "ticket": return long ? "NEW TICKET" : "NEW"
        default: return kind.uppercased()
        }
    }

    private var color: Color { KindBadge.color(kind) }

    static func color(_ kind: String) -> Color {
        switch kind {
        case "amendment": return .purple
        case "renewal": return .teal
        case "revision": return .indigo
        default: return .accentColor
        }
    }
}

/// One item (a repository, a branch, an operation) as a chip.
struct Chip: View {
    let text: String
    var tint: Color = .secondary
    var mono = false

    var body: some View {
        Text(text)
            .font(.system(size: 12, design: mono ? .monospaced : .default))
            .foregroundStyle(.primary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.horizontal, 7)
            .padding(.vertical, 2)
            .background(RoundedRectangle(cornerRadius: 5).fill(tint.opacity(0.14)))
            .textSelection(.enabled)
    }
}

/// Views laid out left to right, wrapping to the next line when the width runs out.
struct Flow: Layout {
    var spacing: CGFloat = 5

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? .infinity
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0, widest: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(ProposedViewSize(width: width, height: nil))
            if x > 0 && x + size.width > width {
                x = 0
                y += line + spacing
                line = 0
            }
            x += size.width + spacing
            line = max(line, size.height)
            widest = max(widest, x - spacing)
        }
        return CGSize(width: min(widest, width), height: y + line)
    }

    func placeSubviews(
        in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
    ) {
        var x: CGFloat = 0, y: CGFloat = 0, line: CGFloat = 0
        for view in subviews {
            let size = view.sizeThatFits(ProposedViewSize(width: bounds.width, height: nil))
            if x > 0 && x + size.width > bounds.width {
                x = 0
                y += line + spacing
                line = 0
            }
            view.place(
                at: CGPoint(x: bounds.minX + x, y: bounds.minY + y),
                proposal: ProposedViewSize(width: min(size.width, bounds.width), height: size.height))
            x += size.width + spacing
            line = max(line, size.height)
        }
    }
}

/// A rounded card.
struct Card<Content: View>: View {
    var tint: Color? = nil
    var padding: CGFloat = 12
    @ViewBuilder let content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(tint.map { $0.opacity(0.06) } ?? Color(nsColor: .controlBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .strokeBorder((tint ?? Color.secondary).opacity(tint == nil ? 0.2 : 0.4))
            )
    }
}

/// A small upper-case label.
struct Caption: View {
    let text: String
    var body: some View {
        Text(text.uppercased())
            .font(.system(size: 10.5, weight: .semibold))
            .tracking(0.3)
            .foregroundStyle(.secondary)
    }
}

/// A row's value: its items as chips, or its text; a time as how far and the clock time.
struct Value: View {
    let row: DocRow
    var mono = false

    var body: some View {
        if let at = Times.date(row.at) {
            TimelineView(.periodic(from: .now, by: 30)) { context in
                Text("\(Times.relative(at, now: context.date)) · \(Times.clock(at, now: context.date))")
                    .font(.system(size: 13))
            }
        } else if let items = row.items, !items.isEmpty {
            Flow {
                ForEach(Array(items.enumerated()), id: \.offset) { _, item in
                    Chip(text: item, mono: mono)
                }
            }
        } else {
            Text(row.value)
                .font(.system(size: 13, design: mono ? .monospaced : .default))
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
    }
}

/// A label and its value, side by side.
struct LabelledRow: View {
    let row: DocRow
    var width: CGFloat = 140

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(row.label ?? "")
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .frame(width: width, alignment: .leading)
            if row.tag == "warning" {
                Label {
                    Text(row.value).font(.system(size: 12.5))
                } icon: {
                    Image(systemName: "exclamationmark.triangle.fill")
                }
                .foregroundStyle(.orange)
                .textSelection(.enabled)
            } else {
                Value(row: row)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// A section that folds: closed at first unless told otherwise; a click on its header opens it.
struct Folding<Content: View>: View {
    let title: String
    let summary: String
    var tint: Color? = nil
    @State var open: Bool
    @ViewBuilder let content: Content

    var body: some View {
        Card(tint: tint, padding: 0) {
            VStack(alignment: .leading, spacing: 0) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(open ? 90 : 0))
                    Text(title).font(.system(size: 13, weight: .semibold))
                    Text(summary)
                        .font(.system(size: 12))
                        .foregroundStyle(tint ?? .secondary)
                        .lineLimit(1)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
                .contentShape(Rectangle())
                .onTapGesture { withAnimation(.easeOut(duration: 0.15)) { open.toggle() } }
                if open {
                    content
                        .padding(.horizontal, 12)
                        .padding(.leading, 18)
                        .padding(.bottom, 12)
                }
            }
        }
    }
}

// MARK: - The window: the rail

/// The tickets waiting, as a narrow rail of badges, oldest first: only when more than one
/// waits. Hovering a badge shows its kind, title and repositories; a click shows it.
struct Rail: View {
    @ObservedObject var model: Model
    @Binding var hovered: String?

    var body: some View {
        VStack(spacing: 8) {
            Text("\(model.waiting.count)")
                .font(.system(size: 11, weight: .bold))
                .foregroundStyle(.secondary)
                .accessibilityLabel("\(model.waiting.count) tickets waiting")
            ScrollView(showsIndicators: false) {
                VStack(spacing: 10) {
                    ForEach(model.waiting) { entry in
                        RailBadge(entry: entry, selected: entry.id == model.shown?.id, hovered: $hovered) {
                            model.pick(entry.id)
                        }
                    }
                }
                .padding(.vertical, 4)
            }
        }
        .padding(.top, 12)
        .frame(width: 58)
        .background(Color(nsColor: .underPageBackgroundColor))
    }
}

/// Where each badge is, for the card shown beside the one hovered.
struct BadgeBounds: PreferenceKey {
    static let defaultValue: [String: Anchor<CGRect>] = [:]
    static func reduce(value: inout [String: Anchor<CGRect>], nextValue: () -> [String: Anchor<CGRect>]) {
        value.merge(nextValue()) { $1 }
    }
}

/// The card beside a hovered badge: its kind, title and repositories. Drawn over the window
/// and never hit: a click always reaches the badge under it (a popover took the first click).
struct HoverCard: View {
    let entry: Entry

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                KindBadge(kind: entry.kind)
                if entry.skipped {
                    Text("put aside").font(.system(size: 10)).foregroundStyle(.secondary)
                }
            }
            Text(entry.title).font(.system(size: 13, weight: .semibold)).lineLimit(3)
            Text(entry.repos.joined(separator: ", "))
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            Text("Click to show it").font(.system(size: 11)).foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(width: 260, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .windowBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.secondary.opacity(0.3)))
        .shadow(color: .black.opacity(0.18), radius: 10, y: 4)
        .allowsHitTesting(false)
    }
}

struct RailBadge: View {
    let entry: Entry
    let selected: Bool
    @Binding var hovered: String?
    let pick: () -> Void

    var body: some View {
        RoundedRectangle(cornerRadius: 9)
            .fill(KindBadge.color(entry.kind).opacity(0.2))
            .frame(width: 38, height: 38)
            .overlay(
                Image(systemName: symbol)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(KindBadge.color(entry.kind))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9)
                    .strokeBorder(Color.accentColor, lineWidth: selected ? 2 : 0)
            )
            .opacity(entry.skipped && !selected ? 0.45 : 1)
            .contentShape(Rectangle())
            .onTapGesture(perform: pick)
            .onHover { inside in hovered = inside ? entry.id : (hovered == entry.id ? nil : hovered) }
            .anchorPreference(key: BadgeBounds.self, value: .bounds) { [entry.id: $0] }
            .accessibilityLabel("\(entry.kind) \(entry.title)")
            .accessibilityAddTraits(.isButton)
    }

    private var symbol: String {
        switch entry.kind {
        case "amendment": return "pencil"
        case "renewal": return "arrow.clockwise"
        case "revision": return "arrow.uturn.backward"
        default: return "plus"
        }
    }
}

// MARK: - The window: what is signed (the centre)

/// The rows of `shown` from the sections of these kinds, the agent's left out.
extension Shown {
    func sections(_ kinds: [String]) -> [DocSection] {
        doc.sections.filter { kinds.contains($0.kind) }
    }

    func row(_ kind: String, _ label: String) -> DocRow? {
        sections([kind]).lazy.flatMap(\.rows).first { $0.label == label }
    }

    func writs(_ section: DocSection) -> [DocRow] {
        section.rows.filter { !agentTags.contains($0.tag) }
    }
}

struct Header: View {
    let shown: Shown

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    KindBadge(kind: shown.kind, long: true)
                    if let lease = shown.row("ticket", "amends lease") ?? shown.row("ticket", "renews lease") {
                        Text("\(lease.label == "amends lease" ? "to" : "of") lease \(lease.value)")
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
                Text("“\(shown.title)”")
                    .font(.system(size: 19, weight: .semibold))
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                Text("Title written by the agent")
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            if let expires = shown.expires {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    VStack(alignment: .trailing, spacing: 2) {
                        Label(ends(expires, context.date), systemImage: "clock")
                            .font(.system(size: 15, weight: .semibold))
                        Text(Times.clock(expires, now: context.date))
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
    }

    private func ends(_ date: Date, _ now: Date) -> String {
        date <= now ? "Expired" : "Ends \(Times.relative(date, now: now))"
    }
}

/// What a change does, first for an amendment, a revision or a renewal: each term's items
/// removed and added, each whole, and how many stay; a value's before → after.
struct ChangesCard: View {
    let shown: Shown
    let section: DocSection

    var body: some View {
        let rows = shown.writs(section)
        Card(tint: .changeTint) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "arrow.left.arrow.right").foregroundStyle(Color.changeTint)
                    Text(heading).font(.system(size: 13, weight: .bold))
                    Text(section.title).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                }
                if rows.isEmpty {
                    Text("Only the agent's words change: see the right pane.")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                ForEach(Array(groups(rows).enumerated()), id: \.offset) { _, group in
                    Divider()
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Caption(text: group.label).frame(width: 140, alignment: .leading)
                        GroupView(rows: group.rows)
                    }
                }
            }
        }
    }

    private var heading: String {
        switch shown.kind {
        case "amendment": return "What changes if you sign"
        case "renewal": return "What the renewal changes"
        case "revision": return "What changed since the refused revision"
        default: return "What changes"
        }
    }

    private struct Change { let label: String; var rows: [DocRow] }

    /// Consecutive rows of one term (and one repository, over several): one change.
    private func groups(_ rows: [DocRow]) -> [Change] {
        var out: [Change] = []
        for row in rows {
            let label = row.repo.map { "\($0) · \(row.label ?? "")" } ?? (row.label ?? "")
            if out.last?.label == label { out[out.count - 1].rows.append(row) } else {
                out.append(Change(label: label, rows: [row]))
            }
        }
        return out
    }

    private struct GroupView: View {
        let rows: [DocRow]

        var body: some View {
            let removed = rows.filter { $0.tag == "removed" }
            let added = rows.filter { $0.tag == "added" }
            let kept = rows.filter { $0.tag == "context" }
            VStack(alignment: .leading, spacing: 4) {
                if removed.count == 1, added.count == 1, kept.isEmpty {
                    // One value for another: before → after.
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        side(removed[0], added: false)
                        Image(systemName: "arrow.right").font(.system(size: 11)).foregroundStyle(.secondary)
                        side(added[0], added: true)
                    }
                } else {
                    ForEach(Array((removed + added).enumerated()), id: \.offset) { _, row in
                        line(row)
                    }
                    ForEach(Array(kept.enumerated()), id: \.offset) { _, row in
                        Text("\(row.value), unchanged").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                }
            }
        }

        private func side(_ row: DocRow, added: Bool) -> some View {
            Group {
                if let at = Times.date(row.at) {
                    TimelineView(.periodic(from: .now, by: 30)) { context in
                        Text("\(Times.relative(at, now: context.date)) (\(Times.clock(at, now: context.date)))")
                    }
                } else {
                    Text(row.value)
                }
            }
            .font(.system(size: 13, weight: added ? .semibold : .regular))
            .foregroundStyle(added ? Color.addedTint : Color.secondary)
            .strikethrough(!added)
            .textSelection(.enabled)
        }

        private func line(_ row: DocRow) -> some View {
            let added = row.tag == "added"
            let tint = added ? Color.addedTint : Color.removedTint
            return HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(added ? "+" : "−").font(.system(size: 13, weight: .bold)).foregroundStyle(tint)
                Text(row.value)
                    .font(.system(size: 12.5, design: .monospaced))
                    .strikethrough(!added)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 5).fill(tint.opacity(0.12)))
        }
    }
}

/// Every enforced term, as a tile: the summary's, the lease's key and violation rule, each
/// repository's largest push. None folded away.
struct Terms: View {
    let shown: Shown

    var body: some View {
        if shown.sections(["repository"]).count > 1 {
            ManyRepositories(shown: shown)
        } else {
            one
        }
    }

    private var one: some View {
        Card(tint: .accentColor) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "signature").foregroundStyle(Color.accentColor)
                    Text(shown.kind == "ticket" ? "You are signing" : "The lease if you sign: every term")
                        .font(.system(size: 13, weight: .bold))
                    Text("enforced by the daemon, whatever the agent wrote")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                TileGrid(tiles: tiles, perRow: 3)
            }
        }
    }

    /// The tiles, by `writ`'s labels: the app picks rows, it never reads a value.
    private var tiles: [(String, DocRow)] {
        let names: [(String, String)] = [
            ("repos", "Repositories"), ("branches", "Branches"), ("operations", "May"),
            ("limits", "Limits"), ("committer name", "Commits as"), ("committer emails", "Commit email"),
            ("templates", "Template"), ("force push", "Force push"),
        ]
        var out: [(String, DocRow)] = names.compactMap { label, name in
            shown.row("signing", label).map { (name, $0) }
        }
        if let key = shown.row("lease", "signing key") { out.append(("Signing key", key)) }
        if let rule = shown.row("lease", "on violation") { out.append(("On violation", rule)) }
        if let rate = shown.row("lease", "max ops per minute") { out.append(("Per minute", rate)) }
        let repositories = shown.sections(["repository"])
        for section in repositories {
            if let size = section.rows.first(where: { $0.label == "max push size" }) {
                let name = repositories.count > 1 ? "Largest push · \(section.title)" : "Largest push"
                out.append((name, size))
            }
        }
        return out
    }
}

/// A lease over several repositories (M7.9.5): the lease's own terms in one strip, then one
/// card per repository with its terms and its paths; an amendment's cards it changes marked,
/// the others folded to a line.
struct ManyRepositories: View {
    let shown: Shown

    var body: some View {
        Card(tint: .accentColor) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "signature").foregroundStyle(Color.accentColor)
                    Text(shown.kind == "ticket" ? "You are signing" : "The lease if you sign: every term")
                        .font(.system(size: 13, weight: .bold))
                    Text("enforced by the daemon, whatever the agent wrote")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Caption(text: "The lease · for every repository")
                TileGrid(tiles: lease)
                ForEach(shown.sections(["repository"]), id: \.self) { section in
                    RepositoryCard(
                        section: section,
                        changed: changed.contains(section.repo ?? ""),
                        folded: !changed.isEmpty && !changed.contains(section.repo ?? ""))
                }
            }
        }
    }

    /// The lease's own terms, by `writ`'s labels.
    private var lease: [(String, DocRow)] {
        let wanted: [(String, String, String)] = [
            ("lease", "committer name", "Commits as"), ("lease", "committer emails", "Commit email"),
            ("lease", "signing key", "Signing key"), ("lease", "max ops per minute", "Per minute"),
            ("lease", "on violation", "On violation"),
        ]
        return wanted.compactMap { kind, label, name in shown.row(kind, label).map { (name, $0) } }
    }

    /// The repositories an amendment's (or a revision's, a renewal's) changes name.
    private var changed: Set<String> {
        Set(shown.sections(["changes"]).flatMap(\.rows).compactMap(\.repo))
    }
}

/// Tiles in balanced rows that fill the width (five as three and two, never four and a lone
/// one), every tile as tall as the tallest, so the strip reads as one block.
struct TileGrid: View {
    let tiles: [(String, DocRow)]
    var perRow = 4

    var body: some View {
        TileRows(perRow: perRow, spacing: 8) {
            ForEach(Array(tiles.enumerated()), id: \.offset) { _, tile in
                Tile(title: tile.0, row: tile.1)
            }
        }
    }
}

/// The layout behind `TileGrid`: rows of at most `perRow`, the first rows taking one more
/// when they can't all hold as many; each view as wide as its row shares and as tall as the
/// tallest view at its width.
struct TileRows: Layout {
    var perRow: Int
    var spacing: CGFloat

    /// How many views each row holds.
    private func rows(_ count: Int) -> [Int] {
        guard count > 0 else { return [] }
        let most = max(perRow, 1)
        let lines = (count + most - 1) / most
        let base = count / lines, extra = count % lines
        return (0..<lines).map { $0 < extra ? base + 1 : base }
    }

    /// Each view's width in a row of `count` across `width`.
    private func width(_ width: CGFloat, _ count: Int) -> CGFloat {
        max((width - spacing * CGFloat(count - 1)) / CGFloat(count), 0)
    }

    /// The width, each view's width, and the common height.
    private func measure(_ proposal: ProposedViewSize, _ subviews: Subviews) -> (CGFloat, [CGFloat], CGFloat) {
        let total = proposal.replacingUnspecifiedDimensions().width
        var widths: [CGFloat] = []
        for count in rows(subviews.count) {
            widths.append(contentsOf: Array(repeating: width(total, count), count: count))
        }
        var tallest: CGFloat = 0
        for (view, wide) in zip(subviews, widths) {
            tallest = max(tallest, view.sizeThatFits(ProposedViewSize(width: wide, height: nil)).height)
        }
        return (total, widths, tallest)
    }

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let (total, _, tallest) = measure(proposal, subviews)
        let lines = CGFloat(rows(subviews.count).count)
        return CGSize(width: total, height: lines == 0 ? 0 : tallest * lines + spacing * (lines - 1))
    }

    func placeSubviews(
        in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()
    ) {
        let (_, widths, tallest) = measure(ProposedViewSize(width: bounds.width, height: nil), subviews)
        var views = Array(zip(subviews, widths))[...]
        var y = bounds.minY
        for count in rows(subviews.count) {
            var x = bounds.minX
            for (view, wide) in views.prefix(count) {
                view.place(
                    at: CGPoint(x: x, y: y), anchor: .topLeading,
                    proposal: ProposedViewSize(width: wide, height: tallest))
                x += wide + spacing
            }
            views = views.dropFirst(count)
            y += tallest + spacing
        }
    }
}

/// One tile: a caption, then the row's value (its items as chips); in a `TileGrid`, as tall as
/// the row it is in.
struct Tile: View {
    let title: String
    let row: DocRow

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Caption(text: title)
            Value(row: row, mono: title == "Branches")
        }
        .padding(10)
        .frame(maxWidth: .infinity, minHeight: 58, maxHeight: .infinity, alignment: .topLeading)
        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.22)))
    }
}

/// One repository of the lease: its name and template, its terms as tiles, its paths as a
/// tree; marked when a change is in it, folded to one line when another one's are.
struct RepositoryCard: View {
    let section: DocSection
    let changed: Bool
    @State var folded: Bool
    @State private var closed: Set<String> = []

    init(section: DocSection, changed: Bool, folded: Bool) {
        self.section = section
        self.changed = changed
        _folded = State(initialValue: folded)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                if folded {
                    Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.secondary)
                }
                Text(section.repo ?? section.title).font(.system(size: 14, weight: .bold))
                if let template = row("template") {
                    Text("template \(template.value)").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                if changed {
                    Text("CHANGES")
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(Color.changeTint)
                        .padding(.horizontal, 6)
                        .background(RoundedRectangle(cornerRadius: 4).fill(Color.changeTint.opacity(0.15)))
                }
                if folded {
                    Text("unchanged · \(summary)")
                        .font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(1)
                }
                Spacer()
                if let paths = row("expected paths"), let items = paths.items {
                    Text("\(items.count) path\(items.count == 1 ? "" : "s")")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .contentShape(Rectangle())
            .onTapGesture { if folded { withAnimation(.easeOut(duration: 0.15)) { folded = false } } }
            if !folded {
                Divider()
                VStack(alignment: .leading, spacing: 10) {
                    TileGrid(tiles: tiles)
                    if let paths = row("expected paths"), let tree = paths.tree, !tree.isEmpty {
                        ClickToScroll(height: 240, fade: Color(nsColor: .textBackgroundColor), corner: 8) {
                            VStack(alignment: .leading, spacing: 0) {
                                TreeRows(
                                    nodes: tree, prefix: (section.repo ?? "") + "\u{0}", depth: 0, filter: "",
                                    closed: $closed)
                            }
                            .padding(8)
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
                        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.22)))
                    } else if let paths = row("expected paths") {
                        Tile(title: "Paths it may touch", row: paths)
                    }
                }
                .padding(12)
            }
        }
        .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(changed ? Color.changeTint.opacity(0.5) : Color.secondary.opacity(0.25)))
    }

    private func row(_ label: String) -> DocRow? {
        section.rows.first { $0.label == label }
    }

    /// The repository's terms, by `writ`'s labels.
    private var tiles: [(String, DocRow)] {
        let wanted: [(String, String)] = [
            ("operations", "May"), ("branches", "Branches"), ("max signatures", "Commits"),
            ("max pushes", "Pushes"), ("max push size", "Largest push"), ("force push", "Force push"),
        ]
        return wanted.compactMap { label, name in row(label).map { (name, $0) } }
    }

    /// A folded card's line: its operations and branches, as `writ` sent them.
    private var summary: String {
        ["operations", "branches"].compactMap { row($0)?.value }.joined(separator: " · ")
    }
}

/// The expected paths: a tree (or a list), filtered, scrolling past 320 points once clicked;
/// every path whole. The tree is `writ`'s: the app never splits a path.
struct PathsCard: View {
    let shown: Shown
    @State private var asTree = true
    @State private var filter = ""
    @State private var closed: Set<String> = []

    var body: some View {
        let sources = self.sources
        let count = sources.reduce(0) { $0 + $1.items.count }
        Card(padding: 0) {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 10) {
                    Caption(text: "Paths it may touch")
                    Text("\(count)")
                        .font(.system(size: 12, weight: .bold))
                        .padding(.horizontal, 7)
                        .background(Capsule().fill(Color.secondary.opacity(0.15)))
                    Text(count == 0 ? "none: not checked" : "each path whole, none cut")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                    Spacer()
                    if count > 0 {
                        Picker("", selection: $asTree) {
                            Text("Tree").tag(true)
                            Text("List").tag(false)
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                        .frame(width: 110)
                        .focusable(false)
                        TextField("Filter paths", text: $filter)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(size: 12))
                            .frame(width: 140)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 9)
                if count > 0 {
                    Divider()
                    ClickToScroll(height: 320, fade: Color(nsColor: .controlBackgroundColor), corner: 10) {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(sources.enumerated()), id: \.offset) { _, source in
                                if sources.count > 1 {
                                    Text(source.title)
                                        .font(.system(size: 12, weight: .semibold))
                                        .padding(.top, 6)
                                }
                                if asTree {
                                    TreeRows(
                                        nodes: source.tree, prefix: source.title + "\u{0}", depth: 0,
                                        filter: filter.lowercased(), closed: $closed)
                                } else {
                                    ForEach(source.items.filter(matches), id: \.self) { item in
                                        Text(item)
                                            .font(.system(size: 12.5, design: .monospaced))
                                            .fixedSize(horizontal: false, vertical: true)
                                            .textSelection(.enabled)
                                            .padding(.vertical, 2)
                                    }
                                }
                            }
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
        }
    }

    private func matches(_ item: String) -> Bool {
        filter.isEmpty || item.lowercased().contains(filter.lowercased())
    }

    private struct Source { let title: String; let items: [String]; let tree: [TreeNode] }

    /// The summary's paths (one repository), else each repository's.
    private var sources: [Source] {
        if let row = shown.row("signing", "expected paths"), let tree = row.tree, !tree.isEmpty {
            return [Source(title: "", items: row.items ?? [], tree: tree)]
        }
        return shown.sections(["repository"]).compactMap { section in
            guard let row = section.rows.first(where: { $0.label == "expected paths" }),
                let tree = row.tree, !tree.isEmpty
            else { return nil }
            return Source(title: section.title, items: row.items ?? [], tree: tree)
        }
    }
}

/// A box that scrolls only once clicked, so the wheel over it keeps scrolling the page: macOS
/// gives a nested scroll view every wheel event under the pointer. Past `height`, a fade and a
/// label say there is more to read and how to reach it; clicked, it takes the wheel (an accent
/// border shows it) until the pointer leaves.
struct ClickToScroll<Content: View>: View {
    let height: CGFloat
    let fade: Color
    let corner: CGFloat
    @ViewBuilder let content: Content
    @State private var active = false
    @State private var place = Place()

    /// Where the view is: whether it overflows, and what is hidden above and below.
    struct Place: Equatable {
        var overflows = false
        var above = false
        var below = false
    }

    var body: some View {
        ScrollView {
            content
        }
        .scrollDisabled(!active)
        .scrollIndicators(active ? .automatic : .never)
        .frame(maxHeight: height)
        .onScrollGeometryChange(for: Place.self) { geometry in
            let visible = geometry.visibleRect
            return Place(
                overflows: geometry.contentSize.height > geometry.containerSize.height + 1,
                above: visible.minY > 1,
                below: visible.maxY < geometry.contentSize.height - 1)
        } action: { _, now in
            place = now
        }
        .simultaneousGesture(TapGesture().onEnded { if place.overflows { active = true } })
        .onHover { inside in if !inside { active = false } }
        .overlay(alignment: .top) {
            if place.overflows && place.above {
                LinearGradient(colors: [fade, fade.opacity(0)], startPoint: .top, endPoint: .bottom)
                    .frame(height: 22)
                    .clipShape(UnevenRoundedRectangle(topLeadingRadius: corner, topTrailingRadius: corner))
                    .allowsHitTesting(false)
            }
        }
        .overlay(alignment: .bottom) {
            if place.overflows && (place.below || !active) {
                ZStack(alignment: .bottom) {
                    if place.below {
                        LinearGradient(colors: [fade.opacity(0), fade], startPoint: .top, endPoint: .bottom)
                            .frame(height: 44)
                            .clipShape(UnevenRoundedRectangle(bottomLeadingRadius: corner, bottomTrailingRadius: corner))
                            .allowsHitTesting(false)
                    }
                    Label(
                        active ? "More below" : (place.below ? "More below · click to scroll" : "Click to scroll"),
                        systemImage: active || place.below ? "chevron.down" : "cursorarrow.click"
                    )
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(active ? Color.secondary : Color.accentColor)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 3)
                    .background(Capsule().fill(.regularMaterial))
                    .overlay(Capsule().strokeBorder(Color.secondary.opacity(0.25)))
                    .padding(.bottom, 6)
                    .onTapGesture { active = true }
                }
            }
        }
        .overlay(
            RoundedRectangle(cornerRadius: corner)
                .strokeBorder(Color.accentColor.opacity(active ? 0.7 : 0), lineWidth: 1.5)
                .allowsHitTesting(false)
        )
        .animation(.easeOut(duration: 0.15), value: active)
        .animation(.easeOut(duration: 0.15), value: place)
    }
}

/// One level of a path tree; a folder opens and closes on a click.
struct TreeRows: View {
    let nodes: [TreeNode]
    let prefix: String
    let depth: Int
    let filter: String
    @Binding var closed: Set<String>

    var body: some View {
        ForEach(Array(nodes.enumerated()), id: \.offset) { _, node in
            let key = prefix + node.name
            if filter.isEmpty || TreeRows.matches(node, prefix: prefix, filter: filter) {
                if node.kind == "folder" {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 9, weight: .semibold))
                            .foregroundStyle(.secondary)
                            .rotationEffect(.degrees(closed.contains(key) ? 0 : 90))
                            .frame(width: 10)
                        Image(systemName: "folder.fill").font(.system(size: 12)).foregroundStyle(.blue.opacity(0.7))
                        Text(node.name).font(.system(size: 12.5, weight: .semibold, design: .monospaced))
                        Spacer()
                        Text("\(node.paths)").font(.system(size: 11)).foregroundStyle(.secondary)
                    }
                    .padding(.leading, CGFloat(depth) * 16)
                    .frame(minHeight: 22)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        if closed.contains(key) { closed.remove(key) } else { closed.insert(key) }
                    }
                    if !closed.contains(key) || !filter.isEmpty {
                        TreeRows(
                            nodes: node.children ?? [], prefix: key, depth: depth + 1, filter: filter,
                            closed: $closed)
                    }
                } else {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Spacer().frame(width: 10)
                        Image(systemName: node.kind == "file" ? "doc" : "asterisk")
                            .font(.system(size: 11))
                            .foregroundStyle(node.kind == "file" ? Color.secondary : Color.orange)
                        Text(node.name)
                            .font(.system(size: 12.5, design: .monospaced))
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                        if node.kind == "everything" {
                            badge("everything inside")
                        } else if node.kind == "pattern" {
                            badge("pattern")
                        }
                    }
                    .padding(.leading, CGFloat(depth) * 16)
                    .frame(minHeight: 22)
                }
            }
        }
    }

    private func badge(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 10.5, weight: .semibold))
            .foregroundStyle(.orange)
            .padding(.horizontal, 6)
            .background(RoundedRectangle(cornerRadius: 4).fill(Color.orange.opacity(0.14)))
    }

    /// Whether a path under `node` holds the filter (a folder: any of its paths).
    static func matches(_ node: TreeNode, prefix: String, filter: String) -> Bool {
        let path = (prefix.split(separator: "\u{0}").last.map(String.init) ?? "") + node.name
        if node.kind != "folder" { return path.lowercased().contains(filter) }
        return (node.children ?? []).contains { matches($0, prefix: prefix + node.name, filter: filter) }
    }
}

/// Who asks, in a line: the program behind the session.
struct AskedBy: View {
    let shown: Shown

    var body: some View {
        if let caller = shown.row("who", "caller") {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: "terminal").foregroundStyle(.secondary)
                Text("Asked by").font(.system(size: 13)).foregroundStyle(.secondary)
                Text(caller.value)
                    .font(.system(size: 12.5))
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
    }
}

struct Centre: View {
    let shown: Shown

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Header(shown: shown)
                ForEach(shown.sections(["changes"]), id: \.self) {
                    ChangesCard(shown: shown, section: $0)
                }
                Terms(shown: shown)
                if shown.sections(["repository"]).count <= 1 {
                    PathsCard(shown: shown)
                }
                AskedBy(shown: shown)
                ForEach(shown.sections(["feedback", "renewal"]), id: \.self) { section in
                    let rows = shown.writs(section)
                    if !rows.isEmpty {
                        Card {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(section.title).font(.system(size: 13, weight: .semibold))
                                ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                                    if row.label == nil { Value(row: row) } else { LabelledRow(row: row) }
                                }
                            }
                        }
                    }
                }
                ForEach(shown.sections(["others"]), id: \.self) { section in
                    let warn = section.rows.contains { $0.tag == "warning" }
                    Folding(
                        title: "Other leases from this source",
                        summary: section.rows.isEmpty
                            ? "none" : (warn ? "\(section.rows.count) active, one overlaps" : "\(section.rows.count) active, no overlap"),
                        tint: warn ? .orange : nil, open: warn
                    ) {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(section.rows.enumerated()), id: \.offset) { _, row in
                                LabelledRow(row: row, width: 240)
                            }
                        }
                    }
                }
                Folding(title: "Details", summary: "everything else writ sign shows", open: false) {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(shown.sections(["ticket", "who", "lease", "repository"]), id: \.self) { section in
                            let rows = shown.writs(section)
                            if !rows.isEmpty {
                                VStack(alignment: .leading, spacing: 6) {
                                    Text(section.title).font(.system(size: 12, weight: .bold))
                                    ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                                        LabelledRow(row: row)
                                    }
                                }
                            }
                        }
                        Button("Copy as text") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(shown.display, forType: .string)
                        }
                        .buttonStyle(.link)
                        .font(.system(size: 12))
                        .focusable(false)
                    }
                }
            }
            .padding(20)
        }
    }
}

// MARK: - The window: the agent's words (the right pane)

/// Every row of the agent's, from every section, in the order `writ` wrote them: untrusted,
/// shown whole, scrolling on its own so text of any length never moves what is signed.
struct AgentPane: View {
    let shown: Shown

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 5) {
                Text("The agent's words").font(.system(size: 13, weight: .bold))
                HStack(spacing: 6) {
                    Text("untrusted · never enforced")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Color.agentTint)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 1)
                        .background(RoundedRectangle(cornerRadius: 5).fill(Color.agentTint.opacity(0.15)))
                    Text("scrolls on its own").font(.system(size: 11)).foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(Array(rows.enumerated()), id: \.offset) { _, entry in
                        VStack(alignment: .leading, spacing: 6) {
                            Caption(text: caption(entry.0, entry.1))
                            words(entry.1)
                        }
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(width: 330)
        .background(Color(nsColor: .windowBackgroundColor).opacity(0.6))
    }

    /// (caption, row): the section's name when it isn't the agent's own (a change, a renewal).
    private var rows: [(String, DocRow)] {
        shown.doc.sections.flatMap { section in
            // The agent's own title is the header's, quoted: not repeated here.
            section.rows.filter { agentTags.contains($0.tag) && !(section.kind == "agent" && $0.label == "title") }
                .map { row -> (String, DocRow) in
                    let label = row.label ?? ""
                    switch row.tag {
                    case "agent_removed": return ("\(label) · before", row)
                    case "agent_added": return ("\(label) · after", row)
                    default: return (label, row)
                    }
                }
        }
    }

    /// A list of steps says how many: "plan · 9 steps".
    private func caption(_ label: String, _ row: DocRow) -> String {
        guard row.tag == "agent", let steps = row.items, !steps.isEmpty else { return label }
        return "\(label) · \(steps.count) step\(steps.count == 1 ? "" : "s")"
    }

    @ViewBuilder private func words(_ row: DocRow) -> some View {
        if row.tag == "agent", let steps = row.items, !steps.isEmpty {
            // The steps `writ` sent one by one: numbered here, the value never split.
            VStack(alignment: .leading, spacing: 8) {
                ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text("\(index + 1)")
                            .font(.system(size: 11, weight: .bold))
                            .foregroundStyle(.secondary)
                            .frame(width: 20, height: 20)
                            .background(Circle().fill(Color.secondary.opacity(0.16)))
                            .alignmentGuide(.firstTextBaseline) { $0[VerticalAlignment.center] + 4 }
                        Text(step)
                            .font(.system(size: 13))
                            .lineSpacing(2)
                            .fixedSize(horizontal: false, vertical: true)
                            .textSelection(.enabled)
                    }
                }
            }
        } else {
            plain(row)
        }
    }

    @ViewBuilder private func plain(_ row: DocRow) -> some View {
        let text = Text(row.value)
            .font(.system(size: 13))
            .lineSpacing(3)
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
        switch row.tag {
        case "agent_removed":
            text.strikethrough()
                .padding(6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.removedTint.opacity(0.1)))
        case "agent_added":
            text
                .padding(6)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 6).fill(Color.addedTint.opacity(0.12)))
        default:
            text
        }
    }
}

// MARK: - The window: the footer

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
                    Image(systemName: "touchid").foregroundStyle(.secondary)
                    Text(model.armed ? "Signs with \(shown.key), through your ssh-agent" : "Just shown: the buttons wake in a second")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                    Button("Decline…") { model.declining = true }
                        .focusable(false)
                        .controlSize(.large)
                        .disabled(!model.armed || model.busy)
                    Button(signLabel) { model.sign() }
                        .focusable(false)
                        .controlSize(.large)
                        .buttonStyle(.borderedProminent)
                        .disabled(!model.armed || model.busy)
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
        .background(.bar)
    }

    private var signLabel: String {
        switch shown.kind {
        case "amendment": return "Sign amendment"
        case "renewal": return "Sign renewal"
        default: return "Sign"
        }
    }
}

struct Root: View {
    @ObservedObject var model: Model
    @State private var hovered: String?

    var body: some View {
        HStack(spacing: 0) {
            // The rail only when another ticket waits beside the one shown.
            if model.waiting.count > 1 {
                Rail(model: model, hovered: $hovered)
                Divider()
            }
            if let shown = model.shown {
                VStack(spacing: 0) {
                    HStack(spacing: 0) {
                        Centre(shown: shown)
                        Divider()
                        AgentPane(shown: shown)
                    }
                    Divider()
                    Footer(model: model, shown: shown)
                }
            } else {
                VStack(spacing: 8) {
                    Image(systemName: "checkmark.seal").font(.system(size: 30)).foregroundStyle(.secondary)
                    Text("Nothing waits for you.").foregroundStyle(.secondary)
                    if let banner = model.banner { Text(banner.text).font(.system(size: 12)) }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 980, minHeight: 600)
        .overlayPreferenceValue(BadgeBounds.self) { anchors in
            GeometryReader { proxy in
                if let id = hovered, let anchor = anchors[id],
                    let entry = model.waiting.first(where: { $0.id == id })
                {
                    let badge = proxy[anchor]
                    HoverCard(entry: entry)
                        .offset(x: badge.maxX + 10, y: badge.minY)
                }
            }
            .allowsHitTesting(false)
        }
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
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 760),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered, defer: false)
        super.init()
        panel.title = "Writ: waiting for your signature"
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
