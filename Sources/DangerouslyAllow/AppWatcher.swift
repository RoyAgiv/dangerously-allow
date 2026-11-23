import AppKit
import ApplicationServices
import DangerouslyAllowCore

struct AppWatchOptions {
    /// App to watch: a localized name ("ChatGPT") or bundle id
    /// ("com.openai.codex", "com.apple.notificationcenterui").
    var appName: String
    var policy: AllowPolicy = .session
    var dryRun = false
    var stopAfterFirst = false
    var pollInterval: TimeInterval = 0.5
    var neverApprove: [String] = []
    /// Gate cards on recognised wording — see `DesktopOptions`. Off by
    /// default; `--require-trigger` puts it back.
    var requireTrigger = false
    var verbose = false
    var notify = false
    /// Print each window's pruned AX tree once and exit — for capturing the
    /// labels of a card the classifier does not know yet.
    var dump = false
    /// Set for `app <name>`: the card channel only runs for this pinned
    /// identity, and the running app's signature must satisfy its requirement.
    var pinnedApp: ApprovedAppIdentity?
    /// Set for `notifications`: pressing goes through the native-GUI gate,
    /// which cannot attest the banner's poster and therefore declines.
    var nativeGuiChannel: NativeGuiContainment.Channel?
    var gate: NativeGuiGate?
    var probe: AppIdentityProbing = CodeSigningIdentityProbe()
}

/// Polls an app's Accessibility tree, and when an approval card appears —
/// ChatGPT's "Allow once / Always allow / Deny", a notification banner with an
/// Allow action — presses the option the policy allows.
///
/// This is the third channel, next to `Watcher` (TUI menus through tmux) and
/// `AXScanner` (TCC dialogs): a native card inside an app window is neither a
/// terminal drawing nor a system dialog, but it is reachable through AX.
/// Notification banners are a twist: Notification Center exposes a banner's
/// buttons as AX *actions on the banner element*, not as child buttons, so the
/// tree builder surfaces each non-standard action as a synthetic pressable.
final class AppWatcher {
    private let opts: AppWatchOptions
    /// Fingerprints already acted on, pruned each sweep to whatever is still on
    /// screen — the same lingering-frame guard `Watcher` uses, as a set so that
    /// several cards up at once do not make each other forgotten.
    private var handled: Set<String> = []
    private var warnedUnverified = false
    private var warnedNative = false

    private let tree = AXTree()

    init(options: AppWatchOptions) {
        self.opts = options
    }

    func run() {
        if !AXIsProcessTrusted() {
            Log.warn("AXIsProcessTrusted() = false — grant this terminal Accessibility in")
            Log.warn("  System Settings → Privacy & Security → Accessibility")
        }
        Log.info("watching app '\(opts.appName)' for approval cards")
        Log.info("policy: \(opts.policy.rawValue)\(opts.dryRun ? "  (DRY RUN)" : "")")
        if let pinned = opts.pinnedApp {
            Log.info("pinned identity: \(pinned.displayName) \(pinned.bundleID), "
                + "team \(pinned.teamID) — signature required")
        }
        if let channel = opts.nativeGuiChannel {
            Log.info("native channel: \(channel.rawValue) — \(opts.gate?.summary ?? "observe-only")")
        }
        if !opts.neverApprove.isEmpty {
            Log.info("never-approve: \(opts.neverApprove.joined(separator: ", "))")
        }

        var warnedNotRunning = false
        while true {
            let apps = matchingApps()
            if apps.isEmpty {
                if !warnedNotRunning {
                    Log.warn("no running app matches '\(opts.appName)' — waiting for it")
                    warnedNotRunning = true
                }
            } else {
                warnedNotRunning = false
                let pressed = scan(apps)
                if pressed, opts.stopAfterFirst { return }
                // A card often has another behind it; do not sleep out the poll
                // interval before looking.
                if pressed, !opts.dump { continue }
            }
            if opts.dump { return }
            Thread.sleep(forTimeInterval: opts.pollInterval)
        }
    }

    // MARK: - one poll

    /// Presses every card this pass finds. Returns true when it pressed any.
    private func scan(_ apps: [NSRunningApplication]) -> Bool {
        var seen: Set<String> = []
        var pressed = false
        for app in apps {
            if let pinned = opts.pinnedApp, !opts.dump {
                let identity = opts.probe.identity(forPID: app.processIdentifier)
                guard identity?.bundleID == pinned.bundleID,
                      identity?.teamID == pinned.teamID,
                      identity?.satisfiesPinnedRequirement == true
                else {
                    if !warnedUnverified {
                        Log.warn("refusing '\(app.localizedName ?? opts.appName)': its live "
                            + "signature does not satisfy the pinned requirement")
                        warnedUnverified = true
                    }
                    continue
                }
                warnedUnverified = false
            }
            for window in tree.windows(ofPID: app.processIdentifier) {
                guard let root = tree.build(window, within: 1.5) else { continue }
                if opts.dump {
                    Log.info("window of \(app.localizedName ?? "?"):")
                    dump(root, indent: 1)
                    continue
                }
                guard let prompt = card(in: root) else { continue }
                seen.insert(prompt.fingerprint)
                guard handled.insert(prompt.fingerprint).inserted else { continue }
                if handle(prompt, appName: app.localizedName ?? opts.appName,
                          pid: app.processIdentifier) {
                    pressed = true
                    if opts.stopAfterFirst { return true }
                }
            }
        }
        handled.formIntersection(seen)
        return pressed
    }

    /// Route one window the same way the desktop mode does: a native
    /// sheet/dialog is never an in-app card, so `app` mode observes it instead
    /// of pressing it. Only `.card` is returned; everything else is nil.
    private func card(in root: UINode) -> DetectedButtonPrompt? {
        switch DesktopRouter.route(
            window: root,
            cardsAllowed: true,
            policies: DesktopPolicies(dialog: .once, card: opts.policy),
            requireTrigger: opts.requireTrigger
        ) {
        case let .card(prompt):
            return prompt
        case .systemDialog:
            if !warnedNative {
                Log.warn("native dialog surface in '\(opts.appName)' — observe-only; "
                    + "the app channel never presses a native permission dialog")
                warnedNative = true
            }
            return nil
        case .ignored:
            return nil
        }
    }

    /// Returns true when the card was confirmed.
    private func handle(_ prompt: DetectedButtonPrompt, appName: String, pid: pid_t) -> Bool {
        if let blocked = PromptDetector.blockingPattern(
            screen: prompt.fullText,
            neverApprove: NativeGuiContainment.effectiveNeverApprove(opts.neverApprove)
        ) {
            Log.warn("REFUSING — card matches --never-approve /\(blocked)/")
            Log.warn("  leaving for a human: \(prompt.cardText.prefix(140))")
            if opts.notify { Notify.post("Vetoed a card in \(appName)") }
            return false
        }

        if opts.verbose {
            for o in prompt.options {
                let mark = o == prompt.target ? "●" : " "
                Log.info("  \(mark) \(o.label)  [\(o.kind.rawValue)]")
            }
        }

        Log.info("card in \(appName): \(prompt.cardText.prefix(140))")
        guard let target = prompt.target else {
            Log.warn("  nothing on it is acceptable under --policy \(opts.policy.rawValue) — leaving for a human")
            if opts.notify { Notify.post("Card in \(appName) needs a human") }
            return false
        }

        Log.info("  -> pressing \"\(target.label)\" [\(target.kind.rawValue)]")
        if opts.dryRun {
            Log.info("  [dry-run] pressed nothing")
            return false
        }

        // Notification banners are a native channel: the poster is not
        // attestable, so containment declines to press even with a capability.
        if let channel = opts.nativeGuiChannel {
            let decision = opts.gate?.authorize(
                promptFingerprint: prompt.fingerprint,
                promptText: prompt.cardText,
                targetLabel: target.label,
                targetKind: target.kind,
                triggerRecognized: true,
                pid: pid
            ) ?? .observe(.missingCapability)
            guard case let .press(action) = decision else {
                Log.warn("  observe-only — \(channel.rawValue) not pressed (\(decision.reason))")
                if opts.notify { Notify.post("Banner in \(appName) left for a human") }
                return false
            }
            Log.info("  one-use capability \(action.capabilityNonce.prefix(8))… authorises this press")
        }

        guard let err = tree.press(target.id) else {
            Log.error("  lost the element between scan and press — leaving it")
            return false
        }
        if err == .success {
            Log.info("  pressed \"\(target.label)\"")
            return true
        }
        Log.error("  press failed (AXError \(err.rawValue))")
        return false
    }

    private func matchingApps() -> [NSRunningApplication] {
        let all = NSWorkspace.shared.runningApplications
        if let pinned = opts.pinnedApp {
            // Bundle id only: a localized name is not an identity, and a
            // lookalike bundle must not be swept up by a substring match.
            return all.filter { $0.bundleIdentifier == pinned.bundleID }
        }
        let needle = opts.appName.lowercased()
        let exact = all.filter {
            $0.localizedName?.lowercased() == needle || $0.bundleIdentifier?.lowercased() == needle
        }
        if !exact.isEmpty { return exact }
        return all.filter {
            ($0.localizedName?.lowercased().contains(needle) ?? false)
                || ($0.bundleIdentifier?.lowercased().contains(needle) ?? false)
        }
    }

    // MARK: - --dump

    private func dump(_ node: UINode, indent: Int) {
        let hasWords = !node.label.isEmpty || !node.text.isEmpty
        let pressable = tree.isPressable(node.id)
        if hasWords || pressable {
            var line = String(repeating: "  ", count: indent) + node.role
            if !node.label.isEmpty { line += " \"\(node.label.prefix(80))\"" }
            if !node.text.isEmpty { line += " text=\"\(node.text.prefix(80))\"" }
            if pressable {
                line += "  [\(OptionClassifier.classify(node.label).rawValue)]"
            }
            Log.plain(line)
        }
        for child in node.children { dump(child, indent: indent + 1) }
    }
}
