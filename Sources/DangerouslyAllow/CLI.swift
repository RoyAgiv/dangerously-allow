import DangerouslyAllowCore
import Foundation

private let usage = """
dangerously-allow — contained, observe-only-by-default approval for the
permission prompts the ChatGPT and T3 desktop apps put in your way, on macOS

USAGE
  dangerously-allow [options]                     observe the whole desktop

  With no arguments it observes all of it, in one process: the approval cards
  inside the ChatGPT and T3 desktop apps, Allow-style actions on
  notification banners, and the native macOS permission dialogs they trigger on
  the way to controlling your machine ("ChatGPT wants access to control X").

  The whole-desktop default is observe-only: it logs what it sees and presses
  nothing. Native permission dialogs are never pressed unless every
  containment gate passes (see CONTAINMENT); in-app cards are pressed only for
  an approved app you name explicitly with --app plus --approve-cards.

OPTIONS
  --policy once|session|always   which grant to click  (default: session for
                                 cards, once for system dialogs — see POLICY)
  --app <name>                   answer cards in this approved app  (repeatable;
                                 requires --approve-cards; only ChatGPT
                                 (com.openai.codex) and T3 (com.t3tools.t3code)
                                 are pinned)
  --approve-cards                opt in to pressing in-app cards, for the apps
                                 named with --app and verified by code signature
  --never-approve <regex>        refuse if the prompt matches   (repeatable;
                                 required before a native dialog may be pressed)
  --dry-run                      log the plan, press nothing
  --verbose                      print every option and the tier it was given
  --once                         exit after the first approval
  --poll <ms>                    scan interval                  (default: 500)
  --require-trigger              only answer prompts whose wording is recognised
                                 (native dialogs always require this)
  --notify                       macOS notification when left for a human

CONTAINMENT (native permission dialogs and notification banners)
  The native-GUI channel is observe-only by default and in the bare invocation.
  A press needs all of: recognised wording, at least one --never-approve
  pattern, --policy once, a window owned by a pinned app whose code signature
  satisfies its designated requirement, and a one-use capability signed by a
  trusted issuer. There is no flag that skips a gate.

  --native-gui-capability <file>  a signed, short-lived, single-use capability
  --trusted-issuer <sha256>       SHA-256 of an issuer's SPKI DER  (repeatable;
                                  empty = nothing is trusted)
  --task-id <id>                  task the capability must be bound to
  --session-id <id>               optional correlator the capability must match
  --host <name>                   host the capability must be bound to
                                  (default: this machine's host name)
  --replay-store <dir>            one-use nonce ledger directory
  --containment-status            print the resolved containment configuration
                                  as JSON and exit; presses nothing
  --containment-check             evaluate a capability against an installed
                                  app and print the decision as JSON; consumes
                                  the capability's nonce on success, presses
                                  nothing
  --check-app <name|path>         app the check verifies (default: ChatGPT)
  --channel <name>                system-dialog|notification-banner
  --prompt-fingerprint <id>       prompt the check pretends to answer
  --target-label <label>          button the check pretends to press

  CARD PRESS LEDGER  (in-app approval cards)
  A card has no nonce, so a press is claimed by identity: host, signed app
  identity, window identity and prompt fingerprint. The claim is durable, so a
  re-presented card is refused as duplicate_card_press — from a second window,
  another watcher process, or after a restart — for 24 hours.

  --card-claim-check              claim one card presentation and print the
                                  decision as JSON; presses nothing and does not
                                  touch an Accessibility tree
  --card-window <identity>        window identity the claim pretends to see
  --card-prompt <fingerprint>     card fingerprint the claim pretends to see
  --card-app <bundle-id>          app the claim is for (default: the named app)
  --card-team <team-id>           team id the claim is for
  --card-store <dir>              claim directory (default: Application Support)

  Task ids and session ids are correlators, never credentials: the signature,
  the pinned issuer fingerprint, the expiry and the one-use nonce are what
  authorise a press.

ONE CHANNEL AT A TIME
  dangerously-allow gui [options]                 native macOS permission dialogs
  dangerously-allow app <name> [options]          approval cards in one app
  dangerously-allow notifications [options]       notification banners only

  The desktop mode's three channels, separately — mostly useful with --dump,
  which prints an app's pruned AX tree so an unrecognised prompt can be pasted
  into an issue verbatim.

TERMINAL AGENTS (secondary)
  dangerously-allow run [options] <command>       launch an agent in tmux, watcher attached
  dangerously-allow watch <tmux-target> [options] watch an agent already running in tmux

  A CLI agent can usually just be told to allow everything
  (`claude --dangerously-skip-permissions`), so this is for the cases where it
  cannot be: the watcher reads the TUI menu out of a tmux pane and drives it
  with arrow keys.

OPTIONS (run + watch)
  --policy once|session|always   which grant to click        (default: session)
  --never-approve <regex>        refuse if the pane matches  (repeatable)
  --dry-run                      log the plan, send no keys
  --verbose                      print the parsed menu
  --llm-fallback                 ask an LLM to label menus the rules miss
  --llm-model <id>               fallback model      (default: claude-haiku-4-5)
  --notify                       macOS notification when left for a human

OPTIONS (watch only)
  --once                         exit after the first approval
  --poll <ms>                    capture interval            (default: 400)
  --nav-delay <ms>               pause between arrow keys    (default: 80)
  --no-require-trigger           match menus with no question line above
                                 (the tmux path still gates on one by default)

LLM FALLBACK
  Only runs when the rule-based classifier does not recognise a menu. The model
  labels each row (it never picks one); its labels are reconciled with the rule
  engine's, most-reluctant-wins, and the policy then selects the target. The
  policy ceiling and --never-approve veto still apply, and it defers to a human
  when the model, the rules, or the policy disagree. Needs ANTHROPIC_API_KEY (or
  ANTHROPIC_AUTH_TOKEN) in the environment.

OPTIONS (run only)
  --name <name>                  tmux session name           (default: da-<pid>)
  --log <file>                   watcher log destination
  --no-attach                    leave the session detached

OPTIONS (app + notifications)
  --policy / --never-approve / --dry-run / --verbose / --notify / --once /
  --poll / --require-trigger     as above
  --dump                         print the app's pruned AX tree once and exit

  `app <name>` matches a running approved app by name or bundle id and presses
  the option the policy allows on approval cards it shows — e.g. the ChatGPT
  desktop app's "Allow once / Always allow / Deny". Only two identities are
  pinned: ChatGPT (com.openai.codex, team 2DC432GLL2) and T3
  (com.t3tools.t3code, team ARK85ZXQ4Z); the running app's code signature is
  checked against its designated requirement, and any other app is rejected.
  `notifications` does the same for action buttons on macOS notification
  banners, but banners are observe-only: the poster cannot be attested, so the
  containment gate always declines. Both need this terminal to have
  Accessibility permission (System Settings → Privacy & Security →
  Accessibility) — no sudo. A card only counts when it offers both a grant and
  a refusal, like the TUI path.

OPTIONS (gui)
  --policy / --never-approve / --dry-run / --verbose / --dump / --notify /
  --once / --poll / --require-trigger + CONTAINMENT  (--policy default: once)

  gui scans every app for a native permission dialog. It observes and never
  presses unless the containment gates pass, and even then only an explicitly
  one-shot button ("Allow Once") is eligible: a plain "Allow" is a permanent
  TCC grant however mildly it is worded, so this executable never presses one.
  Refusals and neutral buttons ("Open System Settings") are never pressed under
  any policy. Run --verbose to see the dialogs it passed over and why.

POLICY
  once     click "Yes" / "Allow once"
  session  click "Allow for this session"; falls back to a one-time allow
  always   click "Allow for all future sessions" / "don't ask again" / "Trust folder"

  A policy never escalates: --policy session will not click an
  "all future sessions" option just because no session option exists.

  The two desktop channels start from different defaults because the same word
  means different things in each. "Allow once" on an in-app card really is
  one-shot, so cards default to session. "Allow" on a system dialog is written
  to the TCC database and outlives the process — it is a permanent grant however
  mildly it is worded — so the native-GUI channel defaults to once and the
  containment gate refuses anything broader. Passing --policy sets both, but a
  native dialog still needs a valid capability before anything is pressed.

EXAMPLES
  dangerously-allow                               # observe the desktop
  dangerously-allow --dry-run --verbose           # see what it would press
  dangerously-allow --never-approve 'rm -rf' --never-approve 'Full Disk Access'
  dangerously-allow --app ChatGPT --approve-cards  # answer ChatGPT's cards
  dangerously-allow app com.t3tools.t3code        # answer T3's cards
  dangerously-allow gui --containment-status      # what containment resolved
  dangerously-allow app ChatGPT --dump            # print one app's AX tree
  dangerously-allow run claude                    # secondary: a TUI agent in tmux
"""

@main
struct CLI {
    static func main() {
        var args = Array(CommandLine.arguments.dropFirst())
        // No arguments is the point of the tool: start watching everything.
        guard let subcommand = args.first else {
            // The zero-argument invocation is the safe default by construction:
            // it observes, and a capability in the environment does not change
            // that. Opting into a click-capable run needs an explicit channel.
            runDesktop([], bare: true)
            return
        }

        switch subcommand {
        case "-h", "--help", "help":
            Log.plain(usage)
        case "-v", "--version":
            Log.plain("dangerously-allow 0.4.0")
        case "gui":
            args.removeFirst()
            runGui(args)
        case "watch":
            args.removeFirst()
            runWatch(args)
        case "app":
            args.removeFirst()
            runApp(args)
        case "notifications":
            args.removeFirst()
            runNotifications(args)
        case "run":
            args.removeFirst()
            exit(runRun(args))
        default:
            // A leading flag means the desktop mode with options, not a typo:
            // `dangerously-allow --dry-run` has always started watching.
            guard subcommand.hasPrefix("-") else {
                Log.error("unknown subcommand '\(subcommand)'")
                Log.plain(usage)
                exit(2)
            }
            runDesktop(args)
        }
    }

    // MARK: - desktop (the default)

    private static func runDesktop(_ args: [String], bare: Bool = false) {
        var opts = DesktopOptions()
        var containment = ContainmentOptions.fromEnvironment()
        if bare {
            containment.forceObserveOnly = true
        }
        var extraApps: [String] = []
        var approveCards = false
        var i = 0
        func value() -> String { take(args, &i, args[i]) }
        while i < args.count {
            if containment.handle(args[i], value: value) {
                i += 1
                continue
            }
            switch args[i] {
            case "--policy":
                // One flag, both channels — see POLICY in the usage text for
                // why they start from different defaults.
                let policy = parsePolicy(take(args, &i, "--policy"))
                opts.policies = DesktopPolicies(dialog: policy, card: policy)
            case "--app": extraApps.append(take(args, &i, "--app"))
            case "--approve-cards": approveCards = true
            case "--dry-run": opts.dryRun = true
            case "--once": opts.stopAfterFirst = true
            case "--verbose", "-v": opts.verbose = true
            case "--require-trigger": opts.requireTrigger = true
            // Kept so existing invocations keep working: it now names the default.
            case "--no-require-trigger": opts.requireTrigger = false
            case "--never-approve": opts.neverApprove.append(take(args, &i, "--never-approve"))
            case "--poll": opts.pollInterval = (Double(take(args, &i, "--poll")) ?? 500) / 1000
            case "--notify": opts.notify = true
            default:
                Log.error("unknown option '\(args[i])'")
                exit(2)
            }
            i += 1
        }
        // Cards are pressed only for an app the operator named *and* opted into
        // with --approve-cards; a bare invocation names nothing, so it presses
        // nothing anywhere.
        opts.apps = approveCards ? extraApps : []

        containment.policy = opts.policies.dialog
        containment.neverApprove = opts.neverApprove
        if containment.printStatus {
            containment.printStatusJSON(channel: .systemDialog)
        }
        if containment.runCheck {
            containment.printCheckJSON(channel: containment.checkChannel)
        }
        if containment.runCardClaimCheck {
            containment.printCardClaimJSON(defaultBundleID: "", defaultTeamID: "")
        }
        opts.gate = containment.makeGate(channel: .systemDialog)
        opts.cardLedger = FileCardPressLedger(directory: containment.cardDirectory)
        opts.host = containment.host

        signal(SIGINT) { _ in
            Log.plain("")
            Log.info("stopped")
            exit(0)
        }

        DesktopWatcher(options: opts).run()
    }

    /// Pull the value that follows `args[i]`, or exit with a usage error.
    private static func take(_ args: [String], _ i: inout Int, _ name: String) -> String {
        guard i + 1 < args.count else {
            Log.error("\(name) requires a value")
            exit(2)
        }
        i += 1
        return args[i]
    }

    private static func parsePolicy(_ raw: String) -> AllowPolicy {
        guard let policy = AllowPolicy(rawValue: raw) else {
            Log.error("--policy must be once|session|always, got '\(raw)'")
            exit(2)
        }
        return policy
    }

    // MARK: - watch

    private static func runWatch(_ args: [String]) {
        guard let target = args.first, !target.hasPrefix("-") else {
            Log.error("watch requires a tmux target, e.g. `dangerously-allow watch my-session`")
            exit(2)
        }

        var opts = WatchOptions(target: target)
        var i = 1
        while i < args.count {
            switch args[i] {
            case "--policy": opts.policy = parsePolicy(take(args, &i, "--policy"))
            case "--dry-run": opts.dryRun = true
            case "--once": opts.stopAfterFirst = true
            case "--verbose", "-v": opts.verbose = true
            case "--require-trigger": opts.requireTrigger = true
            // Kept so existing invocations keep working: it now names the default.
            case "--no-require-trigger": opts.requireTrigger = false
            case "--never-approve": opts.neverApprove.append(take(args, &i, "--never-approve"))
            case "--poll": opts.pollInterval = (Double(take(args, &i, "--poll")) ?? 400) / 1000
            case "--nav-delay": opts.navDelay = (Double(take(args, &i, "--nav-delay")) ?? 80) / 1000
            case "--llm-fallback": opts.llmModel = opts.llmModel ?? "claude-haiku-4-5"
            case "--llm-model": opts.llmModel = take(args, &i, "--llm-model")
            case "--notify": opts.notify = true
            default:
                Log.error("unknown option '\(args[i])'")
                exit(2)
            }
            i += 1
        }

        signal(SIGINT) { _ in
            Log.plain("")
            Log.info("stopped")
            exit(0)
        }

        do {
            try Watcher(options: opts).run()
        } catch {
            Log.error("\(error)")
            exit(1)
        }
    }

    // MARK: - gui

    private static func runGui(_ args: [String]) {
        var opts = GuiWatchOptions()
        var containment = ContainmentOptions.fromEnvironment()
        var i = 0
        func value() -> String { take(args, &i, args[i]) }
        while i < args.count {
            if containment.handle(args[i], value: value) {
                i += 1
                continue
            }
            switch args[i] {
            case "--policy": opts.policy = parsePolicy(take(args, &i, "--policy"))
            case "--dry-run": opts.dryRun = true
            case "--once": opts.stopAfterFirst = true
            case "--verbose", "-v": opts.verbose = true
            case "--dump": opts.dump = true
            case "--require-trigger": opts.requireTrigger = true
            // Kept so existing invocations keep working: it now names the default.
            case "--no-require-trigger": opts.requireTrigger = false
            case "--never-approve": opts.neverApprove.append(take(args, &i, "--never-approve"))
            case "--poll": opts.pollInterval = (Double(take(args, &i, "--poll")) ?? 500) / 1000
            case "--notify": opts.notify = true
            default:
                Log.error("unknown option '\(args[i])'")
                exit(2)
            }
            i += 1
        }

        containment.policy = opts.policy
        containment.neverApprove = opts.neverApprove
        if containment.printStatus {
            containment.printStatusJSON(channel: .systemDialog)
        }
        if containment.runCheck {
            containment.printCheckJSON(channel: containment.checkChannel)
        }
        if containment.runCardClaimCheck {
            containment.printCardClaimJSON(defaultBundleID: "", defaultTeamID: "")
        }
        opts.gate = containment.makeGate(channel: .systemDialog)

        signal(SIGINT) { _ in
            Log.plain("")
            Log.info("stopped")
            exit(0)
        }

        AXScanner.run(options: opts)
    }

    // MARK: - app / notifications

    private static func runApp(_ args: [String]) {
        guard let name = args.first, !name.hasPrefix("-") else {
            Log.error("app requires an app name or bundle id, e.g. `dangerously-allow app ChatGPT`")
            exit(2)
        }
        guard let pinned = NativeGuiContainment.approvedApp(named: name) else {
            Log.error("'\(name)' is not an approved app — refusing to answer its cards")
            Log.error("  approved: " + NativeGuiContainment.approvedApps
                .map { "\($0.displayName) (\($0.bundleID), team \($0.teamID))" }
                .joined(separator: "; "))
            exit(2)
        }
        var base = AppWatchOptions(appName: pinned.bundleID)
        base.pinnedApp = pinned
        watchApp(base, Array(args.dropFirst()), containment: ContainmentOptions())
    }

    private static func runNotifications(_ args: [String]) {
        // Notification banners live in Notification Center's process, and their
        // buttons are AX actions on the banner element — AppWatcher knows how.
        // The poster cannot be attested from the banner, so this channel is
        // observe-only: the containment gate always declines to press.
        var base = AppWatchOptions(appName: "com.apple.notificationcenterui")
        base.nativeGuiChannel = .notificationBanner
        watchApp(base, args, containment: ContainmentOptions.fromEnvironment())
    }

    private static func watchApp(
        _ base: AppWatchOptions, _ args: [String], containment: ContainmentOptions?
    ) {
        var opts = base
        var containment = containment
        var i = 0
        func value() -> String { take(args, &i, args[i]) }
        while i < args.count {
            if var current = containment, current.handle(args[i], value: value) {
                containment = current
                i += 1
                continue
            }
            switch args[i] {
            case "--policy": opts.policy = parsePolicy(take(args, &i, "--policy"))
            case "--dry-run": opts.dryRun = true
            case "--once": opts.stopAfterFirst = true
            case "--verbose", "-v": opts.verbose = true
            case "--require-trigger": opts.requireTrigger = true
            // Kept so existing invocations keep working: it now names the default.
            case "--no-require-trigger": opts.requireTrigger = false
            case "--never-approve": opts.neverApprove.append(take(args, &i, "--never-approve"))
            case "--poll": opts.pollInterval = (Double(take(args, &i, "--poll")) ?? 500) / 1000
            case "--notify": opts.notify = true
            case "--dump": opts.dump = true
            default:
                Log.error("unknown option '\(args[i])'")
                exit(2)
            }
            i += 1
        }

        if var resolved = containment {
            resolved.policy = opts.policy
            resolved.neverApprove = opts.neverApprove
            if resolved.printStatus {
                resolved.printStatusJSON(channel: opts.nativeGuiChannel ?? .systemDialog)
            }
            if resolved.runCheck {
                resolved.printCheckJSON(channel: resolved.checkChannel)
            }
            if resolved.runCardClaimCheck {
                resolved.printCardClaimJSON(
                    defaultBundleID: opts.pinnedApp?.bundleID ?? "",
                    defaultTeamID: opts.pinnedApp?.teamID ?? ""
                )
            }
            opts.cardLedger = FileCardPressLedger(directory: resolved.cardDirectory)
            opts.host = resolved.host
            if let channel = opts.nativeGuiChannel {
                opts.gate = resolved.makeGate(channel: channel)
            }
        }

        signal(SIGINT) { _ in
            Log.plain("")
            Log.info("stopped")
            exit(0)
        }

        AppWatcher(options: opts).run()
    }

    // MARK: - run

    private static func runRun(_ args: [String]) -> Int32 {
        var opts = RunOptions(sessionName: "da-\(getpid())", command: [])
        var i = 0
        loop: while i < args.count {
            switch args[i] {
            case "--name": opts.sessionName = take(args, &i, "--name")
            case "--log": opts.logPath = take(args, &i, "--log")
            case "--no-attach": opts.attach = false
            case "--policy":
                let raw = take(args, &i, "--policy")
                _ = parsePolicy(raw) // validate here so the child cannot fail late
                opts.watchArgs += ["--policy", raw]
            case "--never-approve":
                opts.watchArgs += ["--never-approve", take(args, &i, "--never-approve")]
            case "--dry-run": opts.watchArgs.append("--dry-run")
            case "--verbose": opts.watchArgs.append("--verbose")
            case "--llm-fallback": opts.watchArgs.append("--llm-fallback")
            case "--llm-model": opts.watchArgs += ["--llm-model", take(args, &i, "--llm-model")]
            case "--notify": opts.watchArgs.append("--notify")
            case "--":
                i += 1
                break loop
            default:
                // The first bare token starts the agent's own command line.
                if args[i].hasPrefix("-") {
                    Log.error("unknown option '\(args[i])'")
                    return 2
                }
                break loop
            }
            i += 1
        }

        opts.command = Array(args[i...])
        guard !opts.command.isEmpty else {
            Log.error("run requires a command, e.g. `dangerously-allow run claude`")
            return 2
        }
        return Runner.run(opts)
    }
}
