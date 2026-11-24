import Foundation

/// An explicit, owner-authored authorization to answer native macOS consent
/// dialogs. The containment gate's signed one-use capability remains the
/// default path; this type exists because the fleet owner asked for unattended
/// approval of *every* consent dialog (file access, removable volumes,
/// automation, screen recording, accessibility, camera, microphone, …), which
/// a per-press capability cannot express: the prompt may appear at any time and
/// nobody is present to sign it.
///
/// The file is the authorization. It must be owned by the executing user, must
/// not be group- or world-writable, and must say `Enabled: true`. A command-line
/// flag alone never enables the mode, so a stray argument cannot widen a
/// watcher that was installed without the owner's intent.
///
/// What this never does:
/// * press a refusal or a neutral button (`Don't Allow`, `Cancel`, `Open System
///   Settings`) — those are structurally unreachable in `SystemDialogDetector`;
/// * answer password, Keychain, Touch ID, FileVault, Apple Account, sudo or
///   administrator-authentication prompts — the hard block below wins even when
///   the operator's own `--never-approve` list does not mention them;
/// * press an arbitrary app window. A dialog qualifies only when it belongs to
///   a system consent host, or carries recognised consent wording *and* offers
///   a refusal/neutral way out.
public struct OwnerConsent: Equatable {
    public static let schema = "hyde-owner-consent/v1"

    /// The prompt families no consent file may approve. These are genuine
    /// authentication/secret prompts, not consent grants.
    public static let hardBlock = #"(?i)(password|passphrase|keychain|credential|secret|private[ -]?key|touch[ -]?id|filevault|apple[ -]?id|sudo|administrat(?:or|ion)|authenticate|authoriz|unlock|erase|signing|system extension)"#

    /// Windows owned by these processes are the system's own consent UI.
    public static let systemConsentHosts: Set<String> = [
        "com.apple.UserNotificationCenter",
        "com.apple.tccd",
        "com.apple.CoreServicesUIAgent",
        "com.apple.systemuiserver",
        "com.apple.SecurityAgent",
        "com.apple.controlcenter",
        "com.apple.notificationcenterui",
    ]

    public let path: String
    /// A TCC "Allow" is permanent. The owner either accepted that or not.
    public let allowPermanent: Bool
    /// Extra owner patterns, applied on top of the hard block.
    public let neverApprove: [String]

    public init(path: String, allowPermanent: Bool, neverApprove: [String]) {
        self.path = path
        self.allowPermanent = allowPermanent
        self.neverApprove = neverApprove
    }

    public static func load(
        path: String,
        fileManager: FileManager = .default,
        effectiveUID: uid_t = geteuid()
    ) throws -> OwnerConsent {
        let attributes: [FileAttributeKey: Any]
        do {
            attributes = try fileManager.attributesOfItem(atPath: path)
        } catch {
            throw OwnerConsentError.unreadable(path)
        }
        guard attributes[.type] as? FileAttributeType == .typeRegular else {
            throw OwnerConsentError.notARegularFile(path)
        }
        if let owner = attributes[.ownerAccountID] as? NSNumber,
           owner.uint32Value != effectiveUID {
            throw OwnerConsentError.wrongOwner(path)
        }
        if let mode = attributes[.posixPermissions] as? NSNumber,
           mode.uint16Value & 0o077 != 0 {
            throw OwnerConsentError.insecurePermissions(path)
        }
        guard let data = fileManager.contents(atPath: path),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw OwnerConsentError.malformed(path)
        }
        guard object["Schema"] as? String == schema,
              object["Enabled"] as? Bool == true
        else {
            throw OwnerConsentError.notEnabled(path)
        }
        let permanent = object["Allow_Permanent"] as? Bool == true
        var patterns: [String] = []
        if let list = object["Never_Approve"] as? [String] {
            patterns = list.filter { !$0.isEmpty && $0.count <= 512 }
        }
        return OwnerConsent(path: path, allowPermanent: permanent, neverApprove: patterns)
    }

    /// The effective veto list: the operator's command-line patterns, this
    /// file's patterns and the unremovable authentication block.
    public func vetoPatterns(operatorPatterns: [String]) -> [String] {
        NativeGuiContainment.effectiveNeverApprove(
            operatorPatterns + neverApprove + [OwnerConsent.hardBlock]
        )
    }

    /// A dialog may be answered only when it is a real consent surface. A
    /// random app's `OK` button is a small dialog with a granting option too,
    /// so shape alone is not enough: either the system owns the window, or the
    /// wording is recognised *and* the user is offered a way out.
    public static func isConsentDialog(
        dialog: DetectedSystemDialog,
        bundleID: String?,
        triggerRecognized: Bool
    ) -> Bool {
        if let bundleID, systemConsentHosts.contains(bundleID) { return true }
        let hasRefusal = dialog.options.contains { !$0.kind.grantsAccess && $0.kind != .neutral }
        let hasNeutral = dialog.options.contains { $0.kind == .neutral }
        return triggerRecognized && (hasRefusal || hasNeutral)
    }
}

public enum OwnerConsentError: Error, CustomStringConvertible, Equatable {
    case unreadable(String)
    case notARegularFile(String)
    case wrongOwner(String)
    case insecurePermissions(String)
    case malformed(String)
    case notEnabled(String)

    public var description: String {
        switch self {
        case let .unreadable(path): return "owner consent unreadable: \(path)"
        case let .notARegularFile(path): return "owner consent is not a regular file: \(path)"
        case let .wrongOwner(path): return "owner consent is not owned by this user: \(path)"
        case let .insecurePermissions(path): return "owner consent must be mode 0600: \(path)"
        case let .malformed(path): return "owner consent is not valid JSON: \(path)"
        case let .notEnabled(path): return "owner consent is not enabled: \(path)"
        }
    }
}

/// Append-only audit trail for owner-consent presses. One line per decision,
/// owner-only permissions, no prompt body (only a short fingerprint digest).
public struct OwnerConsentAudit {
    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    public static func defaultDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/state/hyde-approval-watchers", isDirectory: true)
    }

    public func record(
        app: String,
        bundleID: String?,
        fingerprint: String,
        target: String,
        kind: String,
        host: String,
        outcome: String,
        now: Date = Date()
    ) {
        let manager = FileManager.default
        try? manager.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let object: [String: Any] = [
            "ts": formatter.string(from: now),
            "host": host,
            "category": "owner_consent",
            "app": String(app.prefix(120)),
            "bundle_id": bundleID ?? NSNull(),
            "prompt_sha256": NativeGuiContainment.sha256Hex(fingerprint),
            "target": String(target.prefix(80)),
            "kind": kind,
            "outcome": outcome,
            "passwords_used": false,
            "system_permission_changed": outcome == "pressed",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
              var line = String(data: data, encoding: .utf8)
        else { return }
        line += "\n"
        let file = directory.appendingPathComponent("consent-audit.jsonl")
        if !manager.fileExists(atPath: file.path) {
            manager.createFile(atPath: file.path, contents: nil,
                               attributes: [.posixPermissions: 0o600])
        }
        guard let handle = try? FileHandle(forWritingTo: file) else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data(line.utf8))
    }
}
