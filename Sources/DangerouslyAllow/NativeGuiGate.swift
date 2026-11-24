import AppKit
import DangerouslyAllowCore
import Foundation
import Security

/// Reads a running (or on-disk) app's code signature and answers two questions
/// the containment gate needs: who is this really, and does it satisfy the
/// pinned designated requirement?
///
/// A name, a bundle path and a window title are all attacker-controlled. The
/// only thing trusted here is the signature the kernel validated at exec time.
protocol AppIdentityProbing {
    func identity(forPID pid: pid_t) -> NativeGuiContainment.ObservedApp?
    func identity(forBundleAt path: String) -> NativeGuiContainment.ObservedApp?
}

struct CodeSigningIdentityProbe: AppIdentityProbing {
    func identity(forPID pid: pid_t) -> NativeGuiContainment.ObservedApp? {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid as String: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code
        else {
            return fallbackIdentity(forPID: pid)
        }
        return describe(code, fallbackBundleID: NSRunningApplication(processIdentifier: pid)?.bundleIdentifier)
    }

    func identity(forBundleAt path: String) -> NativeGuiContainment.ObservedApp? {
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess, let code else {
            return nil
        }
        let bundleID = Bundle(url: URL(fileURLWithPath: path))?.bundleIdentifier
        return describe(code, fallbackBundleID: bundleID)
    }

    /// When the Security API cannot even describe the process, report the bundle
    /// id with `satisfiesPinnedRequirement: false` so the gate can name the app
    /// in its denial instead of failing silently.
    private func fallbackIdentity(forPID pid: pid_t) -> NativeGuiContainment.ObservedApp? {
        guard let bundleID = NSRunningApplication(processIdentifier: pid)?.bundleIdentifier,
              !bundleID.isEmpty
        else { return nil }
        return NativeGuiContainment.ObservedApp(
            bundleID: bundleID, satisfiesPinnedRequirement: false
        )
    }

    private func describe(_ code: SecCode, fallbackBundleID: String?) -> NativeGuiContainment.ObservedApp? {
        // A running process's SecCode is the same CoreFoundation object a
        // static-code query wants; Swift imports the two opaque types strictly,
        // so bridge once, here, and nowhere else.
        describe(
            staticCode: unsafeBitCast(code, to: SecStaticCode.self),
            fallbackBundleID: fallbackBundleID
        ) { requirement in
            SecCodeCheckValidity(code, [], requirement) == errSecSuccess
        }
    }

    private func describe(_ code: SecStaticCode, fallbackBundleID: String?) -> NativeGuiContainment.ObservedApp? {
        describe(staticCode: code, fallbackBundleID: fallbackBundleID) { requirement in
            SecStaticCodeCheckValidity(code, [], requirement) == errSecSuccess
        }
    }

    private func describe(
        staticCode: SecStaticCode,
        fallbackBundleID: String?,
        validity: (SecRequirement) -> Bool
    ) -> NativeGuiContainment.ObservedApp? {
        var information: CFDictionary?
        let flags = SecCSFlags(
            rawValue: kSecCSSigningInformation | kSecCSRequirementInformation
        )
        guard SecCodeCopySigningInformation(staticCode, flags, &information) == errSecSuccess,
              let info = information as? [String: Any]
        else {
            guard let fallbackBundleID, !fallbackBundleID.isEmpty else { return nil }
            return NativeGuiContainment.ObservedApp(
                bundleID: fallbackBundleID, satisfiesPinnedRequirement: false
            )
        }

        let identifier = (info[kSecCodeInfoIdentifier as String] as? String)
            ?? fallbackBundleID ?? ""
        guard !identifier.isEmpty else { return nil }
        let team = info[kSecCodeInfoTeamIdentifier as String] as? String

        guard let pinned = NativeGuiContainment.approvedApp(bundleID: identifier) else {
            // Not a pinned app at all: still report its identity so the gate's
            // denial says "app_not_approved" rather than "unverified".
            return NativeGuiContainment.ObservedApp(
                bundleID: identifier, teamID: team, satisfiesPinnedRequirement: false
            )
        }

        var requirementSHA256: String?
        if let requirement = info[kSecCodeInfoDesignatedRequirement as String] {
            var data: CFData?
            if SecRequirementCopyData(requirement as! SecRequirement, [], &data) == errSecSuccess,
               let data {
                requirementSHA256 = NativeGuiContainment.sha256Hex(data as Data)
            }
        } else {
            var requirement: SecRequirement?
            if SecCodeCopyDesignatedRequirement(staticCode, [], &requirement) == errSecSuccess,
               let requirement {
                var data: CFData?
                if SecRequirementCopyData(requirement, [], &data) == errSecSuccess, let data {
                    requirementSHA256 = NativeGuiContainment.sha256Hex(data as Data)
                }
            }
        }

        var pinnedRequirement: SecRequirement?
        let satisfied = SecRequirementCreateWithString(
            pinned.designatedRequirement as CFString, [], &pinnedRequirement
        ) == errSecSuccess
            && pinnedRequirement.map(validity) == true

        return NativeGuiContainment.ObservedApp(
            bundleID: identifier,
            teamID: team,
            requirementSHA256: requirementSHA256,
            satisfiesPinnedRequirement: satisfied
        )
    }
}

/// Everything the executable resolved about native-GUI containment before a
/// scan starts: the capability (if any), who may have signed it, the binding
/// fields, and the one-use ledger.
final class NativeGuiGate {
    let channel: NativeGuiContainment.Channel
    let taskID: String
    let sessionID: String
    let host: String
    let neverApprove: [String]
    let policy: AllowPolicy
    let capability: NativeGuiCapabilityEnvelope?
    let capabilityLoadError: String?
    let trustedIssuers: Set<String>
    let ledger: NativeGuiReplayRecording
    let probe: AppIdentityProbing

    init(
        channel: NativeGuiContainment.Channel,
        taskID: String,
        sessionID: String,
        host: String,
        neverApprove: [String],
        policy: AllowPolicy,
        capability: NativeGuiCapabilityEnvelope?,
        capabilityLoadError: String? = nil,
        trustedIssuers: Set<String>,
        ledger: NativeGuiReplayRecording,
        probe: AppIdentityProbing = CodeSigningIdentityProbe()
    ) {
        self.channel = channel
        self.taskID = taskID
        self.sessionID = sessionID
        self.host = host
        self.neverApprove = neverApprove
        self.policy = policy
        self.capability = capability
        self.capabilityLoadError = capabilityLoadError
        self.trustedIssuers = trustedIssuers
        self.ledger = ledger
        self.probe = probe
    }

    /// The static configuration verdict, without touching a prompt or consuming
    /// a capability. Click-capable means "a press could in principle pass every
    /// gate" — not that one will: the prompt, app and signature still have to
    /// match at press time.
    var configurationReasons: [String] {
        var reasons: [String] = []
        if capabilityLoadError != nil { reasons.append("malformed_capability") }
        if capability == nil && capabilityLoadError == nil { reasons.append("missing_capability") }
        if trustedIssuers.isEmpty { reasons.append("untrusted_issuer") }
        if taskID.isEmpty { reasons.append("task_mismatch") }
        if neverApprove.isEmpty { reasons.append("empty_never_approve") }
        if policy != .once { reasons.append("policy_not_one_shot") }
        return reasons
    }

    var isClickCapable: Bool { configurationReasons.isEmpty }

    /// Build a request from what the scanner observed and run the single gate.
    /// `pid` is the process whose window carries the prompt; its signature is
    /// read live, never inferred from a name.
    func authorize(
        promptFingerprint: String,
        promptText: String,
        targetLabel: String,
        targetKind: OptionKind,
        triggerRecognized: Bool,
        pid: pid_t
    ) -> NativeGuiContainment.Decision {
        let observed = probe.identity(forPID: pid)
        let request = NativeGuiContainment.Request(
            channel: channel,
            promptFingerprint: promptFingerprint,
            promptText: promptText,
            targetLabel: targetLabel,
            targetKind: targetKind,
            triggerRecognized: triggerRecognized,
            neverApprove: neverApprove,
            policy: policy,
            host: host,
            taskID: taskID,
            sessionID: sessionID,
            observedApp: observed
        )
        return NativeGuiContainment.evaluate(
            request: request,
            capability: capability,
            trustedIssuerSHA256: trustedIssuers,
            replayLedger: ledger
        )
    }

    /// One-line explanation for the startup log.
    var summary: String {
        if isClickCapable {
            return "observe-only until a valid one-use capability matches a prompt"
        }
        return "observe-only — never presses (\(configurationReasons.joined(separator: ", ")))"
    }
}

/// File-backed one-use ledger. `O_CREAT|O_EXCL` is the atomic bit: two
/// processes presenting the same nonce cannot both create the file, so the
/// second is a replay. Any I/O error denies the press.
final class FileNativeGuiReplayLedger: NativeGuiReplayRecording {
    private let directory: URL

    init(directory: URL) {
        self.directory = directory
    }

    static func defaultDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("dangerously-allow/native-gui-replay", isDirectory: true)
    }

    func consume(nonce: String, expiresAt: Date, now: Date) -> Bool {
        let manager = FileManager.default
        do {
            try manager.createDirectory(
                at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            return false
        }
        pruneExpired(now: now)
        let path = directory.appendingPathComponent(
            NativeGuiContainment.sha256Hex(nonce) + ".json"
        )
        let descriptor = open(path.path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        let record = "{\"Expires_At\":\"\(ISO8601DateFormatter().string(from: expiresAt))\"}"
        _ = record.withCString { pointer in
            write(descriptor, pointer, strlen(pointer))
        }
        return true
    }

    private func pruneExpired(now: Date) {
        let manager = FileManager.default
        guard let entries = try? manager.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil
        ) else { return }
        let parser = ISO8601DateFormatter()
        for entry in entries where entry.pathExtension == "json" {
            guard let data = try? Data(contentsOf: entry),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let raw = object["Expires_At"] as? String,
                  let expires = parser.date(from: raw)
            else { continue }
            if expires <= now {
                try? manager.removeItem(at: entry)
            }
        }
    }
}
