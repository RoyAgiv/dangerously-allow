import AppKit
import DangerouslyAllowCore
import Foundation

/// The native-GUI containment knobs, parsed from the command line and the
/// environment. They are deliberately *not* options the watcher may ignore:
/// `GUI`/desktop mode always consults the gate built here before any press.
struct ContainmentOptions {
    var capabilityPath: String?
    var trustedIssuerSHA256: [String] = []
    var taskID = ""
    var sessionID = ""
    var host = HostEnvironment.resolvedHost()
    var replayDirectory = FileNativeGuiReplayLedger.defaultDirectory()
    var policy: AllowPolicy = .once
    var neverApprove: [String] = []
    var printStatus = false
    var runCheck = false
    /// Set only for the literal zero-argument invocation. A bare run is the
    /// tool's safe default by construction: it ignores even a capability in the
    /// environment and only observes.
    var forceObserveOnly = false
    var checkApp: String?
    var checkChannel: NativeGuiContainment.Channel = .systemDialog
    var checkPromptFingerprint = "containment-diagnostic"
    var checkTargetLabel = "Allow Once"
    /// Card-press ledger diagnostics. `--card-claim-check` runs the same
    /// `CardPressGuard` the watchers use and prints the decision; it presses
    /// nothing and touches no Accessibility tree.
    var runCardClaimCheck = false
    var cardDirectory = FileCardPressLedger.defaultDirectory()
    var cardWindowIdentity = ""
    var cardPromptFingerprint = ""
    var cardAppBundleID = ""
    var cardAppTeamID = ""

    /// Read the environment once, before argv: an explicit flag still wins.
    static func fromEnvironment() -> ContainmentOptions {
        var options = ContainmentOptions()
        let environment = ProcessInfo.processInfo.environment
        if let path = environment["DANGEROUSLY_ALLOW_NATIVE_GUI_CAPABILITY"] {
            options.capabilityPath = path
        }
        if let raw = environment["DANGEROUSLY_ALLOW_TRUSTED_ISSUERS"] {
            options.trustedIssuerSHA256 = raw
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }
        if let task = environment["DANGEROUSLY_ALLOW_TASK_ID"] { options.taskID = task }
        if let session = environment["DANGEROUSLY_ALLOW_SESSION_ID"] { options.sessionID = session }
        return options
    }

    /// Consume a containment flag if `flag` is one. Returns true when the flag
    /// was handled, so the caller's option parser can fall through to its own
    /// cases when it was not. `value` pulls the argument that follows.
    mutating func handle(_ flag: String, value: () -> String) -> Bool {
        switch flag {
        case "--native-gui-capability":
            capabilityPath = value()
        case "--trusted-issuer":
            trustedIssuerSHA256.append(value())
        case "--task-id":
            taskID = value()
        case "--session-id":
            sessionID = value()
        case "--host":
            host = value()
        case "--replay-store":
            replayDirectory = URL(fileURLWithPath: value())
        case "--containment-status":
            printStatus = true
        case "--containment-check":
            runCheck = true
        case "--check-app":
            // Deliberately not `--app`: that one names a card channel, and the
            // containment check must not silently reuse it.
            checkApp = value()
        case "--channel":
            let raw = value()
            guard let channel = NativeGuiContainment.Channel(rawValue: raw) else {
                Log.error("--channel must be system-dialog|notification-banner, got '\(raw)'")
                exit(2)
            }
            checkChannel = channel
        case "--prompt-fingerprint":
            checkPromptFingerprint = value()
        case "--target-label":
            checkTargetLabel = value()
        case "--card-claim-check":
            runCardClaimCheck = true
        case "--card-store":
            cardDirectory = URL(fileURLWithPath: value())
        case "--card-window":
            cardWindowIdentity = value()
        case "--card-prompt":
            cardPromptFingerprint = value()
        case "--card-app":
            cardAppBundleID = value()
        case "--card-team":
            cardAppTeamID = value()
        default:
            return false
        }
        return true
    }

    var trustedIssuers: Set<String> {
        Set(trustedIssuerSHA256.map { $0.lowercased() })
    }

    var capabilityLoadError: String? {
        guard let path = capabilityPath, !path.isEmpty else { return nil }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return "cannot read \(path)"
        }
        guard NativeGuiCapabilityEnvelope.decode(data) != nil else {
            return "malformed capability at \(path)"
        }
        return nil
    }

    var capability: NativeGuiCapabilityEnvelope? {
        guard let path = capabilityPath, !path.isEmpty,
              let data = try? Data(contentsOf: URL(fileURLWithPath: path))
        else { return nil }
        return NativeGuiCapabilityEnvelope.decode(data)
    }

    func makeGate(channel: NativeGuiContainment.Channel) -> NativeGuiGate {
        NativeGuiGate(
            channel: channel,
            taskID: taskID,
            sessionID: sessionID,
            host: host,
            neverApprove: neverApprove,
            policy: policy,
            capability: forceObserveOnly ? nil : capability,
            capabilityLoadError: forceObserveOnly ? nil : capabilityLoadError,
            trustedIssuers: forceObserveOnly ? [] : trustedIssuers,
            ledger: FileNativeGuiReplayLedger(directory: replayDirectory)
        )
    }

    // MARK: - diagnostics (never press)

    func printStatusJSON(channel: NativeGuiContainment.Channel) -> Never {
        let gate = makeGate(channel: channel)
        let payload: [String: Any] = [
            "Mode": gate.isClickCapable ? "click-capable-possible" : "observe-only",
            "Native_Gui_Observe_Only": !gate.isClickCapable,
            "Channel": channel.rawValue,
            "Required_Policy": AllowPolicy.once.rawValue,
            "Requested_Policy": policy.rawValue,
            "Observe_Only_Reasons": gate.configurationReasons,
            "Capability_Configured": capabilityPath?.isEmpty == false,
            "Capability_Decoded": capability != nil,
            "Trusted_Issuer_Count": trustedIssuers.count,
            "Task_Bound": !taskID.isEmpty,
            "Never_Approve_Count": neverApprove.count,
            "Host": host,
            "Approved_Apps": NativeGuiContainment.approvedApps.map(\.bundleID),
            "Approved_App_Requirements": Dictionary(
                uniqueKeysWithValues: NativeGuiContainment.approvedApps.map {
                    ($0.bundleID, $0.requirementSHA256)
                }
            ),
            "Baseline_Never_Approve": NativeGuiContainment.baselineNeverApprove,
        ]
        printJSON(payload)
        exit(0)
    }

    func printCheckJSON(channel: NativeGuiContainment.Channel) -> Never {
        let gate = makeGate(channel: channel)
        let requestedApp = checkApp ?? NativeGuiContainment.approvedApps[0].displayName
        let probe = CodeSigningIdentityProbe()
        let observed: NativeGuiContainment.ObservedApp?
        if let pinned = NativeGuiContainment.approvedApp(named: requestedApp),
           let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: pinned.bundleID) {
            observed = probe.identity(forBundleAt: url.path)
        } else if requestedApp.hasPrefix("/") {
            observed = probe.identity(forBundleAt: requestedApp)
        } else {
            observed = nil
        }
        let targetKind = SystemDialogDetector.classify(checkTargetLabel)
        let request = NativeGuiContainment.Request(
            channel: channel,
            promptFingerprint: checkPromptFingerprint,
            promptText: "",
            targetLabel: checkTargetLabel,
            targetKind: targetKind,
            triggerRecognized: true,
            neverApprove: neverApprove,
            policy: policy,
            host: host,
            taskID: taskID,
            sessionID: sessionID,
            observedApp: observed
        )
        let decision = NativeGuiContainment.evaluate(
            request: request,
            capability: capability,
            trustedIssuerSHA256: trustedIssuers,
            replayLedger: gate.ledger
        )
        let payload: [String: Any] = [
            "Authorized": decision.isAuthorized,
            "Reason": decision.reason,
            "Channel": channel.rawValue,
            "Task_Id": taskID,
            "App_Bundle_Id": observed?.bundleID ?? "",
            "App_Team_Id": observed?.teamID ?? "",
            "App_Identity_Verified": observed?.satisfiesPinnedRequirement ?? false,
            "Capability_Configured": capability != nil,
            "Trusted_Issuer_Count": trustedIssuers.count,
            "Host": host,
        ]
        if case let .press(action) = decision {
            printJSON(payload.merging(["Capability_Nonce": action.capabilityNonce]) { _, new in new })
        } else {
            printJSON(payload)
        }
        exit(0)
    }

    /// Run one card-press claim through the executable's own guard and print
    /// the decision. The watcher consults exactly this guard immediately before
    /// `AXUIElementPerformAction`, so the second claim for a presentation is
    /// the denial that would have stopped a second physical press.
    func printCardClaimJSON(defaultBundleID: String, defaultTeamID: String) -> Never {
        let identity = CardPressIdentity(
            host: host,
            appBundleID: cardAppBundleID.isEmpty ? defaultBundleID : cardAppBundleID,
            appTeamID: cardAppTeamID.isEmpty ? defaultTeamID : cardAppTeamID,
            windowIdentity: cardWindowIdentity,
            promptFingerprint: cardPromptFingerprint.isEmpty
                ? checkPromptFingerprint : cardPromptFingerprint
        )
        let decision = CardPressGuard.claim(
            identity, ledger: FileCardPressLedger(directory: cardDirectory)
        )
        let payload: [String: Any] = [
            "Claimed": decision.isAuthorized,
            "Reason": decision.reason,
            "Host": identity.host,
            "App_Bundle_Id": identity.appBundleID,
            "App_Team_Id": identity.appTeamID,
            "Window_Identity": identity.windowIdentity,
            "Prompt_Fingerprint": identity.promptFingerprint,
            "Ledger_Key": identity.ledgerKey,
            "Retention_Seconds": Int(CardPressGuard.defaultRetention),
            "Ledger_Directory": cardDirectory.path,
        ]
        printJSON(payload)
        exit(0)
    }
}

private func printJSON(_ payload: [String: Any]) {
    guard let data = try? JSONSerialization.data(
        withJSONObject: payload, options: [.sortedKeys, .prettyPrinted]
    ), let text = String(data: data, encoding: .utf8) else {
        Log.error("could not encode containment status")
        exit(1)
    }
    print(text)
    fflush(stdout)
}
