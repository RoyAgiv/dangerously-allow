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

    /// Authentication wording. Applied only when the owner has not set
    /// `Allow_Authentication: true`; the fleet owner did.
    public static let authenticationBlock = #"(?i)(password|passphrase|keychain|credential|secret|private[ -]?key|touch[ -]?id|filevault|apple[ -]?(?:id|account)|\bsign[ -]?in\b|sudo|administrat(?:or|ion)|authenticate|authoriz|unlock|signing|system extension)"#

    /// Destructive maintenance (delete/format a volume or folder, overwrite,
    /// reboot). Lifted by `Allow_Destructive: true`.
    public static let destructiveBlock = #"(?i)(erase (?:the |this )?(?:disk|volume)|delete (?:the |this )?(?:disk|volume|account)|delete all|remove all|format (?:the |this )?(?:disk|volume)|overwrite|shut ?down|reboot|restart now|log out now|sign out now)"#

    /// Whole-machine destruction. Never lifted: no unattended watcher should
    /// erase the Mac it runs on, even under a broad owner authorization.
    public static let catastrophicBlock = #"(?i)(erase all content|erase all data|erase (?:the |this )?mac|erase (?:the |this )?system|factory reset|reset all settings|reinstall macos|format (?:the |this )?macintosh hd|erase all settings)"#

    /// Windows that may receive a typed password. A fabricated dialog owned by
    /// an arbitrary app must never get the secret; only the system's own
    /// authentication surfaces do.
    public static let trustedSecretHosts: Set<String> = [
        "com.apple.SecurityAgent",
        "com.apple.SecurityAgent.helper",
        "com.apple.UserNotificationCenter",
        "com.apple.systempreferences",
        "com.apple.tccd",
        "com.apple.CoreServicesUIAgent",
        "com.apple.loginwindow",
        "com.apple.opendirectoryd",
        "com.apple.controlcenter",
    ]

    /// Wording that marks a password/admin prompt, as opposed to a routine
    /// confirmation that merely happens to contain a text field.
    public static let authenticationWording = #"(?i)(password|passcode|administrator|administrator'?s name|authentication|authenticate|unlock|sign in|keychain|credential|sudo)"#

    public static func isTrustedSecretDialog(bundleID: String?, text: String) -> Bool {
        guard let bundleID, trustedSecretHosts.contains(bundleID) else { return false }
        return text.range(of: authenticationWording, options: .regularExpression) != nil
    }

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
    /// Password / Keychain / Touch ID / FileVault / Apple Account / sudo /
    /// administrator prompts may be answered.
    public let allowAuthentication: Bool
    /// Irreversible destructive confirmations may be answered.
    public let allowDestructive: Bool
    /// Any dialog-shaped window may be answered, not only a system consent
    /// surface or recognised permission wording.
    public let allowAnyDialog: Bool
    /// An optional command that prints a secret on stdout. When present it is
    /// typed into a password field before the grant button is pressed.
    public let secretCommand: [String]
    /// Extra owner patterns, applied on top of the built-in blocks.
    public let neverApprove: [String]

    public init(
        path: String,
        allowPermanent: Bool,
        allowAuthentication: Bool = false,
        allowDestructive: Bool = false,
        allowAnyDialog: Bool = false,
        secretCommand: [String] = [],
        neverApprove: [String]
    ) {
        self.path = path
        self.allowPermanent = allowPermanent
        self.allowAuthentication = allowAuthentication
        self.allowDestructive = allowDestructive
        self.allowAnyDialog = allowAnyDialog
        self.secretCommand = secretCommand
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
        let authentication = object["Allow_Authentication"] as? Bool == true
        let destructive = object["Allow_Destructive"] as? Bool == true
        let anyDialog = object["Allow_Any_Dialog"] as? Bool == true
        var patterns: [String] = []
        if let list = object["Never_Approve"] as? [String] {
            patterns = list.filter { !$0.isEmpty && $0.count <= 512 }
        }
        var command: [String] = []
        if let list = object["Secret_Command"] as? [String] {
            command = list.filter { !$0.isEmpty && $0.count <= 2048 }
            if command.count != list.count { throw OwnerConsentError.malformed(path) }
        }
        return OwnerConsent(
            path: path,
            allowPermanent: permanent,
            allowAuthentication: authentication,
            allowDestructive: destructive,
            allowAnyDialog: anyDialog,
            secretCommand: command,
            neverApprove: patterns
        )
    }

    /// The effective veto list: the operator's command-line patterns, this
    /// file's patterns, and only the built-in blocks the owner did not lift.
    /// The capability path's baseline list is deliberately not added here — it
    /// would silently re-refuse every authentication prompt the owner enabled.
    public func vetoPatterns(operatorPatterns: [String]) -> [String] {
        var patterns = operatorPatterns + neverApprove + [OwnerConsent.catastrophicBlock]
        if !allowAuthentication { patterns.append(OwnerConsent.authenticationBlock) }
        if !allowDestructive { patterns.append(OwnerConsent.destructiveBlock) }
        var seen = Set<String>()
        return patterns.filter { !$0.isEmpty && seen.insert($0).inserted }
    }

    /// Run the configured secret command and return its single line of output.
    /// A command that fails, hangs or prints nothing yields nil, and the caller
    /// presses the grant button without a value. The secret is never logged,
    /// stored or placed in the audit trail.
    public func resolveSecret(timeout: TimeInterval = 5) -> String? {
        guard let executable = secretCommand.first, !secretCommand.isEmpty else { return nil }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = Array(secretCommand.dropFirst())
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return nil }
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { usleep(50_000) }
        if process.isRunning {
            process.terminate()
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let value = (String(data: data, encoding: .utf8) ?? "")
            .trimmingCharacters(in: .newlines)
        return value.isEmpty ? nil : value
    }

    /// A dialog may be answered only when it is a real consent surface. A
    /// random app's `OK` button is a small dialog with a granting option too,
    /// so shape alone is not enough: either the system owns the window, or the
    /// wording is recognised *and* the user is offered a way out.
    public static func isConsentDialog(
        dialog: DetectedSystemDialog,
        bundleID: String?,
        triggerRecognized: Bool,
        allowAny: Bool = false
    ) -> Bool {
        if allowAny { return true }
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
        passwordsUsed: Bool = false,
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
            "passwords_used": passwordsUsed,
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
