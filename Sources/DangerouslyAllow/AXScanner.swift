import AppKit
import ApplicationServices
import DangerouslyAllowCore

struct GuiWatchOptions {
    /// `once` by default. A TCC dialog's plain "Allow" is a permanent grant
    /// however mildly it is worded, so only an explicitly one-shot button is
    /// ever eligible — and even that needs the containment gate's capability.
    var policy: AllowPolicy = .once
    var dryRun = false
    var stopAfterFirst = false
    var pollInterval: TimeInterval = 0.5
    var neverApprove: [String] = []
    /// Gate dialogs on recognised wording — see `DesktopOptions`. Off by
    /// default for discovery, but the containment gate always requires it
    /// before a press.
    var requireTrigger = false
    /// Log every dialog-shaped window and why it was passed over — for
    /// diagnosing wording the keyword list does not know yet.
    var verbose = false
    /// Print every window carrying any text once, then exit.
    var dump = false
    var notify = false
    /// Native-GUI containment. Nil is treated as "no capability", so it can
    /// only observe.
    var gate: NativeGuiGate?
    /// Explicit owner authorization to answer consent dialogs without a
    /// per-press capability. Nil (the default) keeps the capability gate as
    /// the only press path.
    var ownerConsent: OwnerConsent?
    /// The host recorded in the consent audit trail.
    var host: String = ProcessInfo.processInfo.hostName
    var consentAudit: OwnerConsentAudit? = OwnerConsentAudit(directory: OwnerConsentAudit.defaultDirectory())
}

/// Auto-clicks native macOS TCC dialogs (Microphone, Screen Recording,
/// Accessibility, …). These are real AppKit windows, so they are reachable
/// through the Accessibility API — unlike a permission menu drawn *inside* a
/// terminal, which is just text and needs `Watcher`.
///
/// Unlike the other two channels this one has no app to name: a TCC dialog is
/// presented by whichever process the system chose, so every running app is
/// scanned. `SystemDialogDetector` decides what is a dialog, and — because a
/// grant here is written to the TCC database and outlives the process — the
/// channel is observe-only until the containment gate holds a signed one-use
/// capability, and even then only an explicit one-shot button is eligible.
enum AXScanner {
    static func run(options: GuiWatchOptions) {
        Log.info("scanning for macOS permission dialogs\(options.dryRun ? "  (DRY RUN)" : "")")
        Log.info("policy: \(options.policy.rawValue)  poll: \(options.pollInterval)s — Ctrl+C to stop")
        Log.info("native dialogs: \(options.gate?.summary ?? "observe-only — no gate")")
        if options.ownerConsent == nil {
            Log.info("a TCC grant is permanent — a plain \"Allow\" is never pressed; a press")
            Log.info("  needs an explicit one-shot button plus a valid one-use capability")
        }
        if !options.neverApprove.isEmpty {
            Log.info("never-approve: \(options.neverApprove.joined(separator: ", "))")
        }
        if let consent = options.ownerConsent {
            Log.info("owner consent: \(consent.path) "
                + "(permanent grants \(consent.allowPermanent ? "allowed" : "refused"))")
        }

        AXTree.capMessagingTimeout()
        if !AXIsProcessTrusted() {
            Log.warn("AXIsProcessTrusted() = false — re-run with sudo, or grant Accessibility")
        } else {
            // Positive capability evidence for the supervising heartbeat. It
            // is only printed from a context that can actually read windows.
            Log.info("AXIsProcessTrusted() = true")
        }

        let scanner = Scan(options: options)
        while true {
            let pressed = scanner.pass()
            if pressed, options.stopAfterFirst { return }
            if options.dump { return }
            // Dialogs queue: dismissing one uncovers the next, and an app that
            // wants three permissions asks three times. Sleeping the poll
            // interval between them is the whole of the wait, so a pass that
            // pressed something goes straight back round instead.
            if pressed { continue }
            Thread.sleep(forTimeInterval: options.pollInterval)
        }
    }

    /// Back-compat for the bare `dangerously-allow --dry-run` invocation.
    static func run(dryRun: Bool, pollInterval: TimeInterval) {
        run(options: GuiWatchOptions(dryRun: dryRun, pollInterval: pollInterval))
    }

    private final class Scan {
        /// A dialog is frontmost, and its app is normally the active one, so
        /// the sweep starts there and presses as it goes — the alternative is
        /// answering it only after 128 other apps have been asked about their
        /// windows, which measured at two to five seconds.
        private static func rank(_ app: NSRunningApplication, lastAnswered: pid_t) -> Int {
            if app.processIdentifier == lastAnswered { return 0 }
            if app.isActive { return 1 }
            switch app.activationPolicy {
            case .regular: return 2
            case .accessory: return 3
            default: return 4
            }
        }

        /// Ceiling on one app's whole window list. Finder alone spent over two
        /// seconds of a sweep on windows that were never going to be dialogs,
        /// and a dialog is at the front of the list anyway.
        private static let perAppWalk: TimeInterval = 0.6

        private let opts: GuiWatchOptions
        /// The app the last dialog was answered in, swept first next time:
        /// prompts queue, and the next one is nearly always from the same app.
        private var lastAnswered: pid_t = -1
        /// Fingerprints already acted on, pruned each sweep to whatever is
        /// still on screen — a dialog lingers for a frame or two after it is
        /// pressed, and re-pressing it would answer the *next* one by accident.
        /// A set rather than one slot: with several dialogs up at once, a
        /// single slot forgets the first as soon as the second is pressed.
        private var handled: Set<String> = []
        /// Authentication sheets answered lately, keyed by the surface and its
        /// buttons rather than by wording: a sheet that keeps reappearing is a
        /// failing credential, and pressing it forever cannot fix that.
        private var authAttempts: [String: (count: Int, at: Date)] = [:]
        private static let maxAuthAttempts = 3
        private static let authAttemptWindow: TimeInterval = 120
        /// Windows already reported under --verbose, so a 2 Hz poll does not
        /// reprint the same unrecognised dialog forever.
        private var reported: Set<String> = []
        private let tree = AXTree()

        init(options: GuiWatchOptions) {
            self.opts = options
        }

        /// One sweep of every window of every running app. Presses every
        /// dialog it finds — stopping at the first would make a queue of them
        /// drain one poll interval at a time. Returns true when it pressed
        /// anything.
        func pass() -> Bool {
            var seen: Set<String> = []
            var pressed = false
            let started = Date()
            var scanned = 0
            defer {
                if opts.verbose {
                    Log.info("swept \(scanned) apps in "
                        + String(format: "%.1f", Date().timeIntervalSince(started)) + "s")
                }
            }
            let order = NSWorkspace.shared.runningApplications.sorted {
                Self.rank($0, lastAnswered: lastAnswered) < Self.rank($1, lastAnswered: lastAnswered)
            }
            for app in order {
                scanned += 1
                let name = app.localizedName ?? "pid:\(app.processIdentifier)"
                // System Settings hosts inline authentication sheets inside a
                // large window; its AX tree needs a longer, deeper read so the
                // sheet is reached before the budget ends.
                let isSettings = app.bundleIdentifier == "com.apple.systempreferences"
                let appStarted = Date()
                let appDeadline = Date(timeIntervalSinceNow: isSettings ? 8 : Self.perAppWalk)
                defer {
                    let cost = Date().timeIntervalSince(appStarted)
                    if opts.verbose, cost > 0.2 {
                        Log.info("  slow: \(name) took " + String(format: "%.1f", cost) + "s")
                    }
                }
                let windows = tree.windows(ofPID: app.processIdentifier)
                if isSettings, opts.verbose { Log.info("  settings windows: \(windows.count)") }
                for window in windows {
                    // Windows come front-to-back, so a dialog is at the top of
                    // the list; the tail is what runs the clock down.
                    if Date() >= appDeadline, !opts.dump { break }
                    // A permission dialog is a handful of nodes; walking a
                    // whole Electron window to discover it is not one costs a
                    // synchronous round trip per node, and used to stall the
                    // sweep long enough to miss the dialog entirely.
                    guard let root = tree.build(
                        window,
                        budget: isSettings ? 5000 : AXTree.dialogNodes,
                        within: isSettings ? 5 : 0.3,
                        timeout: isSettings ? 2 : nil
                    ), !tree.truncated || opts.dump else { continue }

                    if isSettings, opts.verbose {
                        var sheet = false
                        func findSheet(_ node: UINode) {
                            if node.role == "AXSheet" { sheet = true }
                            for child in node.children { findSheet(child) }
                        }
                        findSheet(root)
                        Log.info("  settings tree root=\(root.role) sheet=\(sheet) truncated=\(tree.truncated)")
                    }
                    let scan = SystemDialogDetector.detectSheet(
                        root: root, policy: opts.policy, requireTrigger: opts.requireTrigger
                    ) ?? SystemDialogDetector.detect(
                        root: root, policy: opts.policy, requireTrigger: opts.requireTrigger
                    )
                    switch scan {
                    case let .dialog(dialog):
                        if opts.dump {
                            report(root, appName: name, note: "dialog", force: true)
                            continue
                        }
                        seen.insert(dialog.fingerprint)
                        guard handled.insert(dialog.fingerprint).inserted else { continue }
                        if handle(dialog, appName: name, pid: app.processIdentifier) {
                            pressed = true
                            lastAnswered = app.processIdentifier
                            if opts.stopAfterFirst { return true }
                        }
                    case let .skipped(reason):
                        if opts.dump {
                            report(root, appName: name, note: describe(reason), force: true)
                        } else if opts.verbose, !isNoise(reason) {
                            report(root, appName: name, note: describe(reason), force: false)
                        }
                    }
                }
            }
            handled.formIntersection(seen)
            return pressed
        }

        /// Returns true when the dialog was confirmed.
        private func handle(_ dialog: DetectedSystemDialog, appName: String, pid: pid_t) -> Bool {
            // Owner consent owns the veto list: it can lift the authentication
            // block deliberately, so the capability path's baseline must not be
            // layered on top of it.
            let veto = opts.ownerConsent?.vetoPatterns(operatorPatterns: opts.neverApprove)
                ?? NativeGuiContainment.effectiveNeverApprove(opts.neverApprove)
            if let blocked = PromptDetector.blockingPattern(
                screen: dialog.fullText,
                neverApprove: veto
            ) {
                Log.warn("REFUSING — dialog matches --never-approve /\(blocked)/")
                Log.warn("  leaving for a human: \(dialog.dialogText.prefix(140))")
                if opts.notify { Notify.post("Vetoed a permission dialog in \(appName)") }
                return false
            }

            Log.info("dialog in \(appName): \(dialog.dialogText.prefix(140))")
            if opts.verbose {
                for o in dialog.options {
                    let mark = o == dialog.target ? "\u{25cf}" : " "
                    Log.info("  \(mark) \(o.label)  [\(o.kind.rawValue)]")
                }
            }

            // An authentication sheet that keeps coming back means the press
            // is not taking (wrong field, rejected credential, withheld
            // secret). Retrying cannot help, and the old sweep did exactly
            // that — once per second, indefinitely.
            let isAuthentication = dialog.passwordField != nil
                || dialog.passwordMethodOption != nil
            if isAuthentication, !authAttemptAllowed(appName, dialog) {
                Log.warn("  authentication sheet returned \(Self.maxAuthAttempts) times — leaving for a human")
                if opts.notify { Notify.post("Authentication in \(appName) needs the owner") }
                opts.consentAudit?.record(
                    app: appName, bundleID: nil, fingerprint: dialog.fingerprint,
                    target: dialog.target?.label ?? "", kind: "authentication", host: opts.host,
                    outcome: "auth_retry_exhausted"
                )
                return false
            }

            // A Touch ID prompt carries no password field until its
            // "Use Password…" switch is pressed. That press grants nothing; it
            // only reveals the fields the next sweep fills.
            if let method = dialog.passwordMethodOption {
                return selectPasswordMethod(
                    dialog, method: method, appName: appName, pid: pid
                )
            }

            guard let target = dialog.target else {
                Log.warn("  nothing on it is acceptable under --policy \(opts.policy.rawValue) — leaving for a human")
                if opts.notify { Notify.post("Permission dialog in \(appName) needs a human") }
                return false
            }

            Log.info("  -> pressing \"\(target.label)\" [\(target.kind.rawValue)]")
            if opts.dryRun {
                Log.info("  [dry-run] pressed nothing")
                return false
            }

            if let consent = opts.ownerConsent {
                return pressUnderOwnerConsent(
                    consent, dialog: dialog, target: target, appName: appName, pid: pid
                )
            }

            // The single native-GUI press path. A dry run returns above, so it
            // never consumes a capability's nonce.
            let decision = opts.gate?.authorize(
                promptFingerprint: dialog.fingerprint,
                promptText: dialog.dialogText,
                targetLabel: target.label,
                targetKind: target.kind,
                triggerRecognized: SystemDialogDetector.hasRecognizedTrigger(dialog.fullText),
                pid: pid
            ) ?? .observe(.missingCapability)
            guard case let .press(action) = decision else {
                Log.warn("  observe-only — not pressed (\(decision.reason))")
                if opts.notify { Notify.post("Permission dialog in \(appName) left for a human") }
                return false
            }
            Log.info("  one-use capability \(action.capabilityNonce.prefix(8))… "
                + "authorises this press (task \(action.taskID))")

            guard let err = tree.press(target.id) else {
                Log.error("  lost the button between scan and press — leaving it")
                return false
            }
            if err == .success {
                Log.info("  pressed \"\(target.label)\"")
                return true
            }
            Log.error("  press failed (AXError \(err.rawValue))")
            return false
        }

        /// Count authentication presses per surface, not per wording: the
        /// credential is the thing that failed, and only a human can supply a
        /// different one. The window bounds a long-running watcher so a later,
        /// legitimate prompt is not blocked by an old failure.
        private func authAttemptAllowed(_ appName: String, _ dialog: DetectedSystemDialog) -> Bool {
            let key = appName + "\u{a7}"
                + dialog.options.map(\.label).sorted().joined(separator: "|")
            let now = Date()
            var entry = authAttempts[key] ?? (count: 0, at: now)
            if now.timeIntervalSince(entry.at) > Self.authAttemptWindow { entry.count = 0 }
            entry.count += 1
            entry.at = now
            authAttempts[key] = entry
            return entry.count <= Self.maxAuthAttempts
        }

        /// "Use Password…" on a Touch ID sheet. Pressing it grants nothing and
        /// dismisses nothing; it swaps the authentication method so the next
        /// sweep can fill the secure fields. It is only worth pressing when a
        /// secret is configured — otherwise the owner's own Touch ID prompt is
        /// the better answer.
        private func selectPasswordMethod(
            _ dialog: DetectedSystemDialog,
            method: SystemDialogOption,
            appName: String,
            pid: pid_t
        ) -> Bool {
            let bundleID = CodeSigningIdentityProbe().identity(forPID: pid)?.bundleID
            guard let consent = opts.ownerConsent, consent.allowAuthentication,
                  !consent.secretCommand.isEmpty
            else {
                Log.info("  password method offered; no owner secret to fill it — leaving for a human")
                return false
            }
            guard OwnerConsent.isTrustedSecretDialog(bundleID: bundleID, text: dialog.fullText) else {
                Log.warn("REFUSING — password method on an untrusted surface (\(bundleID ?? "unknown"))")
                if opts.notify { Notify.post("Refused a password method on an untrusted surface") }
                return false
            }
            if let blocked = PromptDetector.blockingPattern(
                screen: dialog.fullText,
                neverApprove: consent.vetoPatterns(operatorPatterns: opts.neverApprove)
            ) {
                Log.warn("REFUSING — password method matches --never-approve /\(blocked)/")
                return false
            }
            Log.info("  -> pressing \"\(method.label)\" to reveal the password fields")
            if opts.dryRun {
                Log.info("  [dry-run] pressed nothing")
                return false
            }
            guard let err = tree.press(method.id), err == .success else {
                Log.error("  could not switch to password entry")
                opts.consentAudit?.record(
                    app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                    target: method.label, kind: "authentication", host: opts.host,
                    outcome: "password_method_failed"
                )
                return false
            }
            opts.consentAudit?.record(
                app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                target: method.label, kind: "authentication", host: opts.host,
                outcome: "password_method_selected"
            )
            return true
        }

        /// Owner-consent path. The file is the authorization; the hard block
        /// and the operator's veto list still apply, and the dialog must be a
        /// real consent surface rather than an arbitrary small window.
        private func pressUnderOwnerConsent(
            _ consent: OwnerConsent,
            dialog: DetectedSystemDialog,
            target: SystemDialogOption,
            appName: String,
            pid: pid_t
        ) -> Bool {
            let bundleID = CodeSigningIdentityProbe().identity(forPID: pid)?.bundleID
            let triggerRecognized = SystemDialogDetector.hasRecognizedTrigger(dialog.fullText)
            guard OwnerConsent.isConsentDialog(
                dialog: dialog, bundleID: bundleID, triggerRecognized: triggerRecognized,
                allowAny: consent.allowAnyDialog
            ) else {
                Log.warn("  owner consent declined — window of \(appName) is not a consent surface")
                return false
            }
            if let blocked = PromptDetector.blockingPattern(
                screen: dialog.fullText,
                neverApprove: consent.vetoPatterns(operatorPatterns: opts.neverApprove)
            ) {
                Log.warn("REFUSING — owner-consent hard block /\(blocked)/")
                Log.warn("  leaving for a human: \(dialog.dialogText.prefix(140))")
                if opts.notify { Notify.post("Owner consent vetoed a prompt in \(appName)") }
                opts.consentAudit?.record(
                    app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                    target: target.label, kind: target.kind.rawValue, host: opts.host,
                    outcome: "vetoed"
                )
                return false
            }
            if target.kind == .allowAlways && !consent.allowPermanent {
                Log.warn("  owner consent allows one-shot grants only — leaving permanent grant")
                if opts.notify { Notify.post("Permanent grant in \(appName) needs the owner") }
                opts.consentAudit?.record(
                    app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                    target: target.label, kind: target.kind.rawValue, host: opts.host,
                    outcome: "permanent_not_authorized"
                )
                return false
            }

            Log.info("  owner consent authorises this press (\(consent.path))")
            let audit = opts.consentAudit
            var passwordsUsed = false
            // Only a secure entry field may receive the secret. An
            // administrator sheet lists the account-name field first; typing
            // there overwrites the name, the password stays empty, and the
            // grant button can never succeed.
            if let field = dialog.passwordField {
                // A password field in an untrusted window is exactly the
                // fabricated-dialog credential-theft shape. Never type into it
                // and do not interact with the window at all.
                guard OwnerConsent.isTrustedSecretDialog(
                    bundleID: bundleID, text: dialog.fullText
                ) else {
                    Log.warn("REFUSING — password field in an untrusted dialog (\(bundleID ?? "unknown"))")
                    if opts.notify { Notify.post("Refused a fabricated password dialog in \(appName)") }
                    audit?.record(
                        app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                        target: target.label, kind: target.kind.rawValue, host: opts.host,
                        outcome: "untrusted_secret_dialog"
                    )
                    return false
                }
                guard let secret = consent.resolveSecret() else {
                    // Pressing a grant with an empty password can only fail,
                    // and a failed authentication sheet stays up, so the next
                    // sweep presses it again. Leave it for a human instead.
                    Log.warn("  password field present but no secret resolved — not pressing the grant button")
                    if opts.notify { Notify.post("Password in \(appName) needs the owner") }
                    audit?.record(
                        app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                        target: target.label, kind: target.kind.rawValue, host: opts.host,
                        outcome: "password_unavailable"
                    )
                    return false
                }
                guard tree.typeInto(field, text: secret, pid: pid) else {
                    Log.warn("  could not fill the password field — not pressing the grant button")
                    audit?.record(
                        app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                        target: target.label, kind: target.kind.rawValue, host: opts.host,
                        outcome: "password_fill_failed"
                    )
                    return false
                }
                passwordsUsed = true
                Log.info("  filled the authentication field from the configured secret command")
                // Let the sheet observe the value before the grant press.
                usleep(150_000)
            } else if !dialog.fields.isEmpty {
                Log.warn("  authentication sheet has no secure field — not typing the secret into a plain field")
            }
            guard let err = tree.press(target.id) else {
                Log.error("  lost the button between scan and press — leaving it")
                audit?.record(
                    app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                    target: target.label, kind: target.kind.rawValue, host: opts.host,
                    outcome: "press_lost", passwordsUsed: passwordsUsed
                )
                return false
            }
            guard err == .success else {
                Log.error("  press failed (AXError \(err.rawValue))")
                audit?.record(
                    app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                    target: target.label, kind: target.kind.rawValue, host: opts.host,
                    outcome: "press_failed", passwordsUsed: passwordsUsed
                )
                return false
            }
            Log.info("  pressed \"\(target.label)\" under owner consent")
            audit?.record(
                app: appName, bundleID: bundleID, fingerprint: dialog.fingerprint,
                target: target.label, kind: target.kind.rawValue, host: opts.host,
                outcome: "pressed", passwordsUsed: passwordsUsed
            )
            return true
        }

        // MARK: - diagnostics

        /// A window with nothing to press, or a whole app's worth of buttons,
        /// says nothing about wording — under --verbose it would drown out the
        /// dialogs that are actually worth looking at. Only --dump prints it.
        private func isNoise(_ reason: SystemDialogSkip) -> Bool {
            if case .notADialog = reason { return true }
            return false
        }

        private func describe(_ reason: SystemDialogSkip) -> String {
            switch reason {
            case let .notADialog(count): return "not a dialog (\(count) buttons)"
            case .noPermissionWording: return "no permission wording — add it to permissionKeywords?"
            case .noGrant: return "no button grants anything"
            }
        }

        /// Print what a window actually looks like through AX, so an
        /// unrecognised dialog can be pasted into an issue verbatim.
        private func report(_ tree: UINode, appName: String, note: String, force: Bool) {
            var texts: [String] = []
            var labels: [String] = []
            walk(tree, texts: &texts, labels: &labels)
            guard force || !texts.isEmpty || !labels.isEmpty else { return }

            let key = appName + "\u{a7}" + labels.joined(separator: "|") + "\u{a7}" + texts.joined(separator: " ")
            if !force, !reported.insert(key).inserted { return }

            Log.info("window of \(appName) — \(note)")
            for t in texts { Log.plain("    text: \(t.prefix(160))") }
            for l in labels {
                Log.plain("    button: \"\(l)\"  [\(SystemDialogDetector.classify(l).rawValue)]")
            }
        }

        private func walk(_ node: UINode, texts: inout [String], labels: inout [String]) {
            if node.role == "AXButton" {
                if !node.label.isEmpty { labels.append(node.label) }
                return
            }
            if !node.label.isEmpty { texts.append(node.label) }
            if !node.text.isEmpty { texts.append(node.text) }
            for child in node.children { walk(child, texts: &texts, labels: &labels) }
        }

    }
}
