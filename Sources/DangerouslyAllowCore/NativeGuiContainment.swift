import CryptoKit
import Foundation

/// Containment for the native-GUI channel: the macOS permission dialogs (TCC)
/// and notification banners this tool can reach through the Accessibility API.
///
/// A press here is not like a press on an in-app approval card. "Allow" on a
/// TCC dialog is written to the TCC database and outlives the process, and a
/// permission-shaped window can belong to *any* process — including a helper
/// nobody supervised. So the executable treats the whole channel as
/// **observe-only** until every gate below passes at the moment of the press:
///
///  1. the prompt wording is one the detector actually recognises;
///  2. the operator supplied at least one `--never-approve` pattern (a baseline
///     set of credential/security phrases is always applied on top);
///  3. the requested policy is `once`, so only an explicitly one-shot button is
///     ever eligible — a permanent "Allow" is never pressed, capability or not;
///  4. the window belongs to an app whose code signature satisfies a pinned
///     designated requirement (ChatGPT or T3, below); and
///  5. a short-lived, single-use, task- and prompt-bound capability signed by a
///     trusted issuer authorises this exact action.
///
/// Nothing here is an authorisation token by itself. `Task_Id` and `Session_Id`
/// are *binding* fields: they narrow what a signature may authorise, and a
/// capability with the right task but no valid signature authorises nothing.
/// There is no code path in which a task id, a session id, an environment
/// variable, or a CLI flag on its own makes the channel click-capable.
///
/// The state is deliberately fail-closed: with no trusted issuer configured —
/// the default, because the fleet has no application-action issuer yet — gate 5
/// can never pass, so `--policy always` and a direct `dangerously-allow gui`
/// invocation both observe and never press.
public enum NativeGuiContainment {
    /// How long a capability may live. A native-GUI action is authorised for
    /// one prompt, and the window between issue and press should be seconds.
    public static let maximumCapabilityLifetime: TimeInterval = 120

    /// Tolerated clock skew when checking `Issued_At`.
    public static let clockSkewTolerance: TimeInterval = 5

    /// Phrases that are always vetoed, even when the operator's own
    /// `--never-approve` list does not mention them. These are the dialogs no
    /// unattended process should ever answer: credentials, the security agent,
    /// and the system settings panes that grant access by hand.
    ///
    /// Matched as case-insensitive regular expressions by
    /// `PromptDetector.blockingPattern`, which is the veto used by every
    /// channel.
    public static let baselineNeverApprove: [String] = [
        "password", "passcode", "touch ?id",
        "keychain", "filevault", "securityagent",
        "system settings", "system preferences",
        "full disk access", "administrator", "\\bsudo\\b",
        "unlock", "erase all", "reset",
    ]

    /// The only apps whose native-GUI actions may ever be considered. The pin is
    /// the *designated requirement itself*, checked live with the Security
    /// framework; the SHA-256 below is derived from that text and is what a
    /// capability binds to. Team ids are the Developer ID teams in the
    /// requirement's `leaf[subject.OU]` clause.
    public static let approvedApps: [ApprovedAppIdentity] = [
        ApprovedAppIdentity(
            displayName: "ChatGPT",
            bundleID: "com.openai.codex",
            teamID: "2DC432GLL2",
            designatedRequirement: "identifier \"com.openai.codex\" and anchor apple generic "
                + "and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ "
                + "and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ "
                + "and certificate leaf[subject.OU] = \"2DC432GLL2\""
        ),
        ApprovedAppIdentity(
            displayName: "T3 Code",
            bundleID: "com.t3tools.t3code",
            teamID: "ARK85ZXQ4Z",
            designatedRequirement: "identifier \"com.t3tools.t3code\" and anchor apple generic "
                + "and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ "
                + "and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ "
                + "and certificate leaf[subject.OU] = ARK85ZXQ4Z"
        ),
    ]

    /// Resolve a name or bundle id to a pinned identity. Localized names are not
    /// stable, so only the exact bundle id, or an unambiguous display name, is
    /// accepted — and the code signature is still checked before it is used.
    public static func approvedApp(named name: String) -> ApprovedAppIdentity? {
        let needle = name.lowercased()
        let exact = approvedApps.filter {
            $0.bundleID.lowercased() == needle || $0.displayName.lowercased() == needle
        }
        if exact.count == 1 { return exact[0] }
        let partial = approvedApps.filter {
            $0.bundleID.lowercased().contains(needle)
                || $0.displayName.lowercased().contains(needle)
        }
        return partial.count == 1 ? partial[0] : nil
    }

    public static func approvedApp(bundleID: String) -> ApprovedAppIdentity? {
        approvedApps.first { $0.bundleID == bundleID }
    }

    /// Effective veto list: the operator's patterns followed by the baseline.
    /// Deduplicated so the log does not repeat a pattern the operator already
    /// supplied.
    public static func effectiveNeverApprove(_ operatorPatterns: [String]) -> [String] {
        var seen = Set<String>()
        return (operatorPatterns + baselineNeverApprove).filter { seen.insert($0).inserted }
    }

    /// What the executable resolved for this press attempt. Every field is
    /// derived from something observed or configured, never from the prompt's
    /// own claim about itself.
    public struct Request {
        public var channel: Channel
        public var promptFingerprint: String
        public var promptText: String
        public var targetLabel: String
        public var targetKind: OptionKind
        /// True only when `SystemDialogDetector` recognised the wording.
        public var triggerRecognized: Bool
        /// The operator's `--never-approve` patterns. The baseline is added by
        /// the caller and is not counted here: an empty list is a denial even
        /// though the baseline alone would veto something.
        public var neverApprove: [String]
        public var policy: AllowPolicy
        public var host: String
        public var taskID: String
        public var sessionID: String
        public var observedApp: ObservedApp?

        public init(
            channel: Channel,
            promptFingerprint: String,
            promptText: String = "",
            targetLabel: String = "",
            targetKind: OptionKind = .allowOnce,
            triggerRecognized: Bool = false,
            neverApprove: [String] = [],
            policy: AllowPolicy = .once,
            host: String = "",
            taskID: String = "",
            sessionID: String = "",
            observedApp: ObservedApp? = nil
        ) {
            self.channel = channel
            self.promptFingerprint = promptFingerprint
            self.promptText = promptText
            self.targetLabel = targetLabel
            self.targetKind = targetKind
            self.triggerRecognized = triggerRecognized
            self.neverApprove = neverApprove
            self.policy = policy
            self.host = host
            self.taskID = taskID
            self.sessionID = sessionID
            self.observedApp = observedApp
        }
    }

    public enum Channel: String, CaseIterable {
        case systemDialog = "system-dialog"
        case notificationBanner = "notification-banner"

        /// The capability action this channel accepts.
        public var capabilityAction: String {
            switch self {
            case .systemDialog: return "system-dialog-approve"
            case .notificationBanner: return "notification-banner-approve"
            }
        }
    }

    /// The app whose window carries the prompt, as observed at press time.
    /// `satisfiesPinnedRequirement` is the live Security-framework check — never
    /// inferred from the app's name, bundle path, or the prompt's wording.
    public struct ObservedApp: Equatable {
        public let bundleID: String
        public let teamID: String?
        public let requirementSHA256: String?
        public let satisfiesPinnedRequirement: Bool

        public init(
            bundleID: String,
            teamID: String? = nil,
            requirementSHA256: String? = nil,
            satisfiesPinnedRequirement: Bool = false
        ) {
            self.bundleID = bundleID
            self.teamID = teamID
            self.requirementSHA256 = requirementSHA256
            self.satisfiesPinnedRequirement = satisfiesPinnedRequirement
        }
    }

    public struct AuthorizedAction: Equatable {
        public let channel: Channel
        public let capabilityNonce: String
        public let taskID: String
        public let appBundleID: String
    }

    public enum Denial: String, Equatable, CaseIterable {
        case missingTrigger = "missing_trigger"
        case emptyNeverApprove = "empty_never_approve"
        case policyNotOneShot = "policy_not_one_shot"
        case missingTarget = "missing_target"
        case nonGrantingTarget = "non_granting_target"
        case appNotApproved = "app_not_approved"
        case appIdentityUnverified = "app_identity_unverified"
        case missingCapability = "missing_capability"
        case malformedCapability = "malformed_capability"
        case untrustedIssuer = "untrusted_issuer"
        case invalidSignature = "invalid_signature"
        case capabilityNotYetValid = "capability_not_yet_valid"
        case capabilityExpired = "capability_expired"
        case capabilityLifetimeTooLong = "capability_lifetime_too_long"
        case taskMismatch = "task_mismatch"
        case hostMismatch = "host_mismatch"
        case appScopeMismatch = "app_scope_mismatch"
        case actionScopeMismatch = "action_scope_mismatch"
        case promptScopeMismatch = "prompt_scope_mismatch"
        case replayedCapability = "replayed_capability"
    }

    public enum Decision: Equatable {
        case observe(Denial)
        case press(AuthorizedAction)

        public var isAuthorized: Bool {
            if case .press = self { return true }
            return false
        }

        public var denial: Denial? {
            if case let .observe(reason) = self { return reason }
            return nil
        }

        public var reason: String {
            switch self {
            case let .observe(reason): return reason.rawValue
            case .press: return "authorized"
            }
        }
    }

    // MARK: - evaluation

    /// The single decision point for a native-GUI press. Everything the channel
    /// knows is passed in; the only side effect is consuming the capability's
    /// nonce, and that happens last, after every other gate has passed.
    public static func evaluate(
        request: Request,
        capability: NativeGuiCapabilityEnvelope?,
        trustedIssuerSHA256: Set<String>,
        replayLedger: NativeGuiReplayRecording,
        now: Date = Date()
    ) -> Decision {
        guard request.triggerRecognized else { return .observe(.missingTrigger) }
        guard !request.neverApprove.isEmpty else { return .observe(.emptyNeverApprove) }
        guard request.policy == .once else { return .observe(.policyNotOneShot) }
        guard !request.targetLabel.isEmpty else { return .observe(.missingTarget) }
        guard request.targetKind.grantsAccess else { return .observe(.nonGrantingTarget) }

        guard let observed = request.observedApp,
              let pinned = approvedApp(bundleID: observed.bundleID)
        else { return .observe(.appNotApproved) }
        guard observed.teamID == pinned.teamID,
              observed.satisfiesPinnedRequirement
        else { return .observe(.appIdentityUnverified) }

        guard let capability else { return .observe(.missingCapability) }
        let payload = capability.payload

        guard capability.schema == NativeGuiCapabilityEnvelope.schema,
              capability.algorithm == NativeGuiCapabilityEnvelope.algorithm,
              payload.domain == NativeGuiCapabilityEnvelope.schema,
              payload.purpose == NativeGuiCapabilityEnvelope.purpose
        else { return .observe(.malformedCapability) }

        guard payload.action == request.channel.capabilityAction else {
            return .observe(.actionScopeMismatch)
        }
        guard payload.taskID == request.taskID, !payload.taskID.isEmpty else {
            return .observe(.taskMismatch)
        }
        guard payload.sessionID == request.sessionID else { return .observe(.taskMismatch) }
        guard !request.host.isEmpty, payload.host == request.host else {
            return .observe(.hostMismatch)
        }
        guard payload.appBundleID == pinned.bundleID,
              payload.appTeamID == pinned.teamID,
              payload.appRequirementSHA256 == pinned.requirementSHA256
        else { return .observe(.appScopeMismatch) }
        guard payload.promptFingerprint == request.promptFingerprint,
              !payload.promptFingerprint.isEmpty
        else { return .observe(.promptScopeMismatch) }

        guard let issued = parseTimestamp(payload.issuedAt),
              let expires = parseTimestamp(payload.expiresAt)
        else { return .observe(.malformedCapability) }
        guard issued.timeIntervalSince(now) <= clockSkewTolerance else {
            return .observe(.capabilityNotYetValid)
        }
        guard expires > now else { return .observe(.capabilityExpired) }
        guard expires > issued, expires.timeIntervalSince(issued) <= maximumCapabilityLifetime else {
            return .observe(.capabilityLifetimeTooLong)
        }
        guard payload.nonce.count >= 16, payload.nonce.count <= 120 else {
            return .observe(.malformedCapability)
        }

        guard let fingerprint = spkiSHA256(pem: capability.issuerPublicKeyPEM) else {
            return .observe(.malformedCapability)
        }
        guard trustedIssuerSHA256.contains(fingerprint) else {
            return .observe(.untrustedIssuer)
        }
        guard verifySignature(capability) else { return .observe(.invalidSignature) }

        // Only now is anything consumed. A denial above cannot burn a nonce.
        guard replayLedger.consume(nonce: payload.nonce, expiresAt: expires, now: now) else {
            return .observe(.replayedCapability)
        }

        return .press(AuthorizedAction(
            channel: request.channel,
            capabilityNonce: payload.nonce,
            taskID: payload.taskID,
            appBundleID: pinned.bundleID
        ))
    }

    // MARK: - crypto

    public static func sha256Hex(_ text: String) -> String {
        sha256Hex(Data(text.utf8))
    }

    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// SHA-256 of the SubjectPublicKeyInfo DER, the same fingerprint shape
    /// macs-connect uses for owner grants: `openssl pkey -pubin -outform DER`.
    public static func spkiSHA256(pem: String) -> String? {
        guard let key = try? P256.Signing.PublicKey(pemRepresentation: pem) else { return nil }
        let der = key.derRepresentation
        // CryptoKit has returned both SPKI (91 bytes, 30 59 …) and the raw
        // X9.62 point (65 bytes, 04 …) for `derRepresentation` across SDKs.
        // Normalise to SPKI so the fingerprint always means the same thing.
        if der.count == 91, der.first == 0x30, der.dropFirst().first == 0x59 {
            return sha256Hex(der)
        }
        guard der.count == 65, der.first == 0x04 else { return nil }
        // 30 59 30 13 06 07 2A8648CE3D0201 06 08 2A8648CE3D030107 03 42 00
        let header: [UInt8] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ]
        return sha256Hex(Data(header) + der)
    }

    /// ES256-DER over the canonical payload bytes, matching the contract
    /// macs-connect's `Check_Runtime_Upgrade_Grant` already uses.
    public static func verifySignature(_ capability: NativeGuiCapabilityEnvelope) -> Bool {
        guard let key = try? P256.Signing.PublicKey(pemRepresentation: capability.issuerPublicKeyPEM),
              let signatureData = Data(base64Encoded: capability.signatureBase64),
              let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureData)
        else { return false }
        let payload = Data(capability.payload.canonicalJSON().utf8)
        return key.isValidSignature(signature, for: payload)
    }

    public static func parseTimestamp(_ value: String) -> Date? {
        let precise = ISO8601DateFormatter()
        precise.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = precise.date(from: value) { return date }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: value)
    }
}

/// A pinned application identity. The designated requirement is the policy;
/// the SHA-256 is what a capability binds to, so a capability minted for
/// `com.openai.codex` cannot be replayed against a different signed build.
public struct ApprovedAppIdentity: Equatable {
    public let displayName: String
    public let bundleID: String
    public let teamID: String
    public let designatedRequirement: String

    public init(displayName: String, bundleID: String, teamID: String, designatedRequirement: String) {
        self.displayName = displayName
        self.bundleID = bundleID
        self.teamID = teamID
        self.designatedRequirement = designatedRequirement
    }

    public var requirementSHA256: String {
        NativeGuiContainment.sha256Hex(designatedRequirement)
    }
}

/// One-use ledger for capability nonces. `consume` must be atomic: two
/// concurrent watchers presenting the same capability may not both succeed.
public protocol NativeGuiReplayRecording: AnyObject {
    func consume(nonce: String, expiresAt: Date, now: Date) -> Bool
}

/// In-memory ledger for tests and for `--containment-check` diagnostics.
public final class InMemoryNativeGuiReplayLedger: NativeGuiReplayRecording {
    private var seen: [String: Date] = [:]

    public init() {}

    public func consume(nonce: String, expiresAt: Date, now: Date) -> Bool {
        seen = seen.filter { $0.value > now }
        guard seen[nonce] == nil else { return false }
        seen[nonce] = expiresAt
        return true
    }
}

/// A signed, single-use authorisation for exactly one native-GUI action.
///
/// Wire shape (all payload values are strings so the canonical JSON is
/// unambiguous):
///
///     {
///       "Schema": "dangerously-allow-native-gui-action/v1",
///       "Algorithm": "ES256-DER",
///       "Payload": {
///         "Domain": "dangerously-allow-native-gui-action/v1",
///         "Purpose": "native-gui-approve",
///         "Host": "hyde-m6-2",
///         "Task_Id": "...", "Session_Id": "...", "Request_Id": "...",
///         "App_Bundle_Id": "com.openai.codex",
///         "App_Team_Id": "2DC432GLL2",
///         "App_Requirement_SHA256": "…",
///         "Action": "system-dialog-approve",
///         "Prompt_Fingerprint": "…",
///         "Nonce": "…", "Issued_At": "…", "Expires_At": "…"
///       },
///       "Signature": "base64 DER",
///       "Issuer_Public_Key_Pem": "-----BEGIN PUBLIC KEY-----…"
///     }
///
/// `Task_Id` and `Session_Id` are correlators, not credentials: the signature,
/// the pinned issuer fingerprint, the expiry and the one-use nonce are what
/// authorise anything.
public struct NativeGuiCapabilityEnvelope: Equatable {
    public static let schema = "dangerously-allow-native-gui-action/v1"
    public static let purpose = "native-gui-approve"

    public struct Payload: Equatable {
        public let domain: String
        public let purpose: String
        public let host: String
        public let taskID: String
        public let sessionID: String
        public let requestID: String
        public let appBundleID: String
        public let appTeamID: String
        public let appRequirementSHA256: String
        public let action: String
        public let promptFingerprint: String
        public let nonce: String
        public let issuedAt: String
        public let expiresAt: String

        public init(
            host: String, taskID: String, sessionID: String, requestID: String,
            appBundleID: String, appTeamID: String, appRequirementSHA256: String,
            action: String, promptFingerprint: String, nonce: String,
            issuedAt: String, expiresAt: String
        ) {
            self.domain = NativeGuiCapabilityEnvelope.schema
            self.purpose = NativeGuiCapabilityEnvelope.purpose
            self.host = host
            self.taskID = taskID
            self.sessionID = sessionID
            self.requestID = requestID
            self.appBundleID = appBundleID
            self.appTeamID = appTeamID
            self.appRequirementSHA256 = appRequirementSHA256
            self.action = action
            self.promptFingerprint = promptFingerprint
            self.nonce = nonce
            self.issuedAt = issuedAt
            self.expiresAt = expiresAt
        }

        /// Sorted keys, no whitespace, string values only — byte-identical to
        /// JavaScript's `JSON.stringify` of the same object, which is what the
        /// macs-connect owner-grant verifier signs over.
        public func canonicalJSON() -> String {
            let fields: [(String, String)] = [
                ("Action", action),
                ("App_Bundle_Id", appBundleID),
                ("App_Requirement_SHA256", appRequirementSHA256),
                ("App_Team_Id", appTeamID),
                ("Domain", domain),
                ("Expires_At", expiresAt),
                ("Host", host),
                ("Issued_At", issuedAt),
                ("Nonce", nonce),
                ("Prompt_Fingerprint", promptFingerprint),
                ("Purpose", purpose),
                ("Request_Id", requestID),
                ("Session_Id", sessionID),
                ("Task_Id", taskID),
            ]
            return "{" + fields.sorted { $0.0 < $1.0 }
                .map { "\"\(escape($0.0))\":\"\(escape($0.1))\"" }
                .joined(separator: ",") + "}"
        }

        private func escape(_ value: String) -> String {
            var out = ""
            for scalar in value.unicodeScalars {
                switch scalar {
                case "\"": out += "\\\""
                case "\\": out += "\\\\"
                case "\u{08}": out += "\\b"
                case "\u{0C}": out += "\\f"
                case "\n": out += "\\n"
                case "\r": out += "\\r"
                case "\t": out += "\\t"
                default:
                    if scalar.value < 0x20 {
                        out += String(format: "\\u%04x", scalar.value)
                    } else {
                        out.unicodeScalars.append(scalar)
                    }
                }
            }
            return out
        }
    }

    public let schema: String
    public let algorithm: String
    public let payload: Payload
    public let signatureBase64: String
    public let issuerPublicKeyPEM: String

    public init(
        schema: String = NativeGuiCapabilityEnvelope.schema,
        algorithm: String = NativeGuiCapabilityEnvelope.algorithm,
        payload: Payload,
        signatureBase64: String,
        issuerPublicKeyPEM: String
    ) {
        self.schema = schema
        self.algorithm = algorithm
        self.payload = payload
        self.signatureBase64 = signatureBase64
        self.issuerPublicKeyPEM = issuerPublicKeyPEM
    }

    public static let algorithm = "ES256-DER"

    /// Exact-key decoding. Unknown or missing keys are a malformed capability,
    /// never a silently defaulted one.
    public static func decode(_ data: Data) -> NativeGuiCapabilityEnvelope? {
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["Schema", "Algorithm", "Payload", "Signature", "Issuer_Public_Key_Pem"],
              let payloadObject = object["Payload"] as? [String: Any],
              Set(payloadObject.keys) == payloadKeys,
              let schema = object["Schema"] as? String,
              let algorithm = object["Algorithm"] as? String,
              let signature = object["Signature"] as? String,
              let pem = object["Issuer_Public_Key_Pem"] as? String,
              let host = payloadObject["Host"] as? String,
              let task = payloadObject["Task_Id"] as? String,
              let session = payloadObject["Session_Id"] as? String,
              let request = payloadObject["Request_Id"] as? String,
              let bundle = payloadObject["App_Bundle_Id"] as? String,
              let team = payloadObject["App_Team_Id"] as? String,
              let requirement = payloadObject["App_Requirement_SHA256"] as? String,
              let action = payloadObject["Action"] as? String,
              let prompt = payloadObject["Prompt_Fingerprint"] as? String,
              let nonce = payloadObject["Nonce"] as? String,
              let issued = payloadObject["Issued_At"] as? String,
              let expires = payloadObject["Expires_At"] as? String,
              payloadObject["Domain"] is String,
              payloadObject["Purpose"] is String
        else { return nil }
        return NativeGuiCapabilityEnvelope(
            schema: schema,
            algorithm: algorithm,
            payload: Payload(
                host: host, taskID: task, sessionID: session, requestID: request,
                appBundleID: bundle, appTeamID: team, appRequirementSHA256: requirement,
                action: action, promptFingerprint: prompt, nonce: nonce,
                issuedAt: issued, expiresAt: expires
            ),
            signatureBase64: signature,
            issuerPublicKeyPEM: pem
        )
    }

    private static let payloadKeys: Set<String> = [
        "Domain", "Purpose", "Host", "Task_Id", "Session_Id", "Request_Id",
        "App_Bundle_Id", "App_Team_Id", "App_Requirement_SHA256", "Action",
        "Prompt_Fingerprint", "Nonce", "Issued_At", "Expires_At",
    ]
}
