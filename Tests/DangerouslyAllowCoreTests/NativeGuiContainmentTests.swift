import CryptoKit
import Foundation
import XCTest
@testable import DangerouslyAllowCore

/// The native-GUI channel's contract. These tests pin the properties the
/// executable relies on: observe-only until every gate passes, no escalation
/// through `--policy always`, no task-id-as-token, and a nonce that is spent
/// exactly once and only by a fully authorised action.
final class NativeGuiContainmentTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let signer = P256.Signing.PrivateKey()
    private let otherSigner = P256.Signing.PrivateKey()

    // MARK: - fixtures

    private func iso(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }

    private var chatGPT: ApprovedAppIdentity {
        NativeGuiContainment.approvedApp(bundleID: "com.openai.codex")!
    }

    private var t3: ApprovedAppIdentity {
        NativeGuiContainment.approvedApp(bundleID: "com.t3tools.t3code")!
    }

    private func observed(
        _ pinned: ApprovedAppIdentity = NativeGuiContainment.approvedApp(
            bundleID: "com.openai.codex"
        )!,
        teamID: String? = nil,
        satisfied: Bool = true
    ) -> NativeGuiContainment.ObservedApp {
        NativeGuiContainment.ObservedApp(
            bundleID: pinned.bundleID,
            teamID: teamID ?? pinned.teamID,
            requirementSHA256: pinned.requirementSHA256,
            satisfiesPinnedRequirement: satisfied
        )
    }

    private func request(
        channel: NativeGuiContainment.Channel = .systemDialog,
        fingerprint: String = "card|Allow Once",
        targetLabel: String = "Allow Once",
        targetKind: OptionKind = .allowOnce,
        triggerRecognized: Bool = true,
        neverApprove: [String] = ["password"],
        policy: AllowPolicy = .once,
        host: String = "hyde-m6-2",
        taskID: String = "task-1",
        sessionID: String = "",
        app: NativeGuiContainment.ObservedApp? = nil
    ) -> NativeGuiContainment.Request {
        NativeGuiContainment.Request(
            channel: channel,
            promptFingerprint: fingerprint,
            promptText: "Some app would like to access your screen.",
            targetLabel: targetLabel,
            targetKind: targetKind,
            triggerRecognized: triggerRecognized,
            neverApprove: neverApprove,
            policy: policy,
            host: host,
            taskID: taskID,
            sessionID: sessionID,
            observedApp: app ?? observed()
        )
    }

    private func payload(
        host: String = "hyde-m6-2",
        taskID: String = "task-1",
        sessionID: String = "",
        requestID: String = "req-1",
        app: ApprovedAppIdentity? = nil,
        action: String = "system-dialog-approve",
        fingerprint: String = "card|Allow Once",
        nonce: String = "0123456789abcdef0123456789abcdef",
        issued: Date? = nil,
        expires: Date? = nil
    ) -> NativeGuiCapabilityEnvelope.Payload {
        let pinned = app ?? chatGPT
        return NativeGuiCapabilityEnvelope.Payload(
            host: host,
            taskID: taskID,
            sessionID: sessionID,
            requestID: requestID,
            appBundleID: pinned.bundleID,
            appTeamID: pinned.teamID,
            appRequirementSHA256: pinned.requirementSHA256,
            action: action,
            promptFingerprint: fingerprint,
            nonce: nonce,
            issuedAt: iso(issued ?? now.addingTimeInterval(-5)),
            expiresAt: iso(expires ?? now.addingTimeInterval(55))
        )
    }

    private func capability(
        _ payload: NativeGuiCapabilityEnvelope.Payload,
        signer: P256.Signing.PrivateKey? = nil,
        schema: String = NativeGuiCapabilityEnvelope.schema
    ) -> NativeGuiCapabilityEnvelope {
        let key = signer ?? self.signer
        let signature = try! key.signature(
            for: Data(payload.canonicalJSON().utf8)
        ).derRepresentation
        return NativeGuiCapabilityEnvelope(
            schema: schema,
            algorithm: NativeGuiCapabilityEnvelope.algorithm,
            payload: payload,
            signatureBase64: signature.base64EncodedString(),
            issuerPublicKeyPEM: key.publicKey.pemRepresentation
        )
    }

    private func trusted(
        _ signer: P256.Signing.PrivateKey? = nil
    ) -> Set<String> {
        let key = signer ?? self.signer
        return [NativeGuiContainment.spkiSHA256(pem: key.publicKey.pemRepresentation)!]
    }

    private func evaluate(
        _ request: NativeGuiContainment.Request,
        _ capability: NativeGuiCapabilityEnvelope?,
        trusted: Set<String>? = nil,
        ledger: InMemoryNativeGuiReplayLedger = InMemoryNativeGuiReplayLedger()
    ) -> NativeGuiContainment.Decision {
        NativeGuiContainment.evaluate(
            request: request,
            capability: capability,
            trustedIssuerSHA256: trusted ?? self.trusted(),
            replayLedger: ledger,
            now: now
        )
    }

    // MARK: - defaults are observe-only

    func testNoCapabilityObserves() {
        XCTAssertEqual(
            evaluate(request(), nil),
            .observe(.missingCapability)
        )
    }

    func testMissingTriggerObserves() {
        XCTAssertEqual(
            evaluate(request(triggerRecognized: false), capability(payload())),
            .observe(.missingTrigger)
        )
    }

    func testEmptyNeverApproveObserves() {
        // The baseline alone is not enough: the operator must supply a pattern.
        XCTAssertEqual(
            evaluate(request(neverApprove: []), capability(payload())),
            .observe(.emptyNeverApprove)
        )
    }

    func testNonOneShotPolicyObservesEvenWithAValidCapability() {
        // This is the executable-level guarantee: --policy always cannot turn
        // the channel click-capable, however well-formed the capability is.
        XCTAssertEqual(
            evaluate(request(policy: .always), capability(payload())),
            .observe(.policyNotOneShot)
        )
        XCTAssertEqual(
            evaluate(request(policy: .session), capability(payload())),
            .observe(.policyNotOneShot)
        )
    }

    func testNonGrantingTargetObserves() {
        XCTAssertEqual(
            evaluate(
                request(targetLabel: "Don't Allow", targetKind: .deny),
                capability(payload())
            ),
            .observe(.nonGrantingTarget)
        )
    }

    func testMissingTargetObserves() {
        XCTAssertEqual(
            evaluate(
                request(targetLabel: "", targetKind: .allowOnce),
                capability(payload())
            ),
            .observe(.missingTarget)
        )
    }

    // MARK: - pinned app identity

    func testUnapprovedAppObserves() {
        let safari = NativeGuiContainment.ObservedApp(
            bundleID: "com.apple.Safari",
            teamID: "59GAB85EFG",
            satisfiesPinnedRequirement: false
        )
        XCTAssertEqual(
            evaluate(request(app: safari), capability(payload())),
            .observe(.appNotApproved)
        )
    }

    func testPinnedBundleWithUnverifiedSignatureObserves() {
        XCTAssertEqual(
            evaluate(request(app: observed(satisfied: false)), capability(payload())),
            .observe(.appIdentityUnverified)
        )
    }

    func testPinnedBundleWithWrongTeamObserves() {
        XCTAssertEqual(
            evaluate(
                request(app: observed(teamID: "ARK85ZXQ4Z")),
                capability(payload())
            ),
            .observe(.appIdentityUnverified)
        )
    }

    func testT3IsPinnedAndUsable() {
        let decision = evaluate(
            request(app: observed(t3)),
            capability(payload(app: t3, action: "system-dialog-approve"))
        )
        XCTAssertTrue(decision.isAuthorized)
    }

    func testApprovedAppsResolveByNameAndBundleID() {
        XCTAssertEqual(NativeGuiContainment.approvedApp(named: "ChatGPT")?.bundleID,
                       "com.openai.codex")
        XCTAssertEqual(NativeGuiContainment.approvedApp(named: "com.openai.codex")?.bundleID,
                       "com.openai.codex")
        XCTAssertEqual(NativeGuiContainment.approvedApp(named: "T3")?.bundleID,
                       "com.t3tools.t3code")
        XCTAssertNil(NativeGuiContainment.approvedApp(named: "Safari"))
        XCTAssertNil(NativeGuiContainment.approvedApp(named: "com.anthropic.claudefordesktop"))
    }

    func testPinnedRequirementHashesAreTheDocumentsSha256() {
        // SHA-256 of the designated-requirement text, the value a capability
        // binds to. Computed from `codesign -d -r- /Applications/…`.
        XCTAssertEqual(chatGPT.requirementSHA256,
                       "a0543f83b3be6dad5f5084a49a300199fd6297b2435ec5f31e1131578cbb158c")
        XCTAssertEqual(t3.requirementSHA256,
                       "33de38ef5bcddca58b592960ff253f567ab994003a233288359b11e362fd5edc")
    }

    // MARK: - capability shape and crypto

    func testUnsupportedSchemaIsMalformed() {
        XCTAssertEqual(
            evaluate(request(), capability(payload(), schema: "other/v1")),
            .observe(.malformedCapability)
        )
    }

    func testUntrustedIssuerObserves() {
        XCTAssertEqual(
            evaluate(request(), capability(payload()), trusted: []),
            .observe(.untrustedIssuer)
        )
        XCTAssertEqual(
            evaluate(request(), capability(payload(), signer: otherSigner)),
            .observe(.untrustedIssuer)
        )
    }

    func testTamperedPayloadFailsTheSignature() {
        let original = payload()
        // Request_Id is a correlator the gate does not compare, so the scope
        // checks all pass and only the signature can catch the change.
        let tampered = payload(requestID: "req-2")
        var envelope = capability(original)
        envelope = NativeGuiCapabilityEnvelope(
            schema: envelope.schema,
            algorithm: envelope.algorithm,
            payload: tampered,
            signatureBase64: envelope.signatureBase64,
            issuerPublicKeyPEM: envelope.issuerPublicKeyPEM
        )
        XCTAssertEqual(
            evaluate(request(), envelope),
            .observe(.invalidSignature)
        )
    }

    func testTaskIDIsNotAnAuthorisationToken() {
        // Correct task, correct app, correct prompt — but no signature.
        var envelope = capability(payload())
        envelope = NativeGuiCapabilityEnvelope(
            schema: envelope.schema,
            algorithm: envelope.algorithm,
            payload: envelope.payload,
            signatureBase64: "AA==",
            issuerPublicKeyPEM: envelope.issuerPublicKeyPEM
        )
        XCTAssertEqual(evaluate(request(), envelope), .observe(.invalidSignature))
    }

    func testExpiredCapabilityObserves() {
        XCTAssertEqual(
            evaluate(
                request(),
                capability(payload(
                    issued: now.addingTimeInterval(-300),
                    expires: now.addingTimeInterval(-60)
                ))
            ),
            .observe(.capabilityExpired)
        )
    }

    func testNotYetValidCapabilityObserves() {
        XCTAssertEqual(
            evaluate(
                request(),
                capability(payload(
                    issued: now.addingTimeInterval(60),
                    expires: now.addingTimeInterval(120)
                ))
            ),
            .observe(.capabilityNotYetValid)
        )
    }

    func testLifetimeLongerThanTwoMinutesObserves() {
        XCTAssertEqual(
            evaluate(
                request(),
                capability(payload(
                    issued: now.addingTimeInterval(-5),
                    expires: now.addingTimeInterval(300)
                ))
            ),
            .observe(.capabilityLifetimeTooLong)
        )
    }

    func testTaskBindingIsEnforced() {
        XCTAssertEqual(
            evaluate(request(taskID: "task-1"), capability(payload(taskID: "task-2"))),
            .observe(.taskMismatch)
        )
        XCTAssertEqual(
            evaluate(request(taskID: ""), capability(payload(taskID: ""))),
            .observe(.taskMismatch)
        )
    }

    func testSessionBindingIsEnforcedButNeverSufficient() {
        XCTAssertEqual(
            evaluate(request(sessionID: "session-a"), capability(payload(sessionID: "session-b"))),
            .observe(.taskMismatch)
        )
        // A session id that matches still needs the signature.
        XCTAssertEqual(
            evaluate(request(sessionID: ""), nil),
            .observe(.missingCapability)
        )
    }

    func testHostBindingIsEnforced() {
        XCTAssertEqual(
            evaluate(request(host: "hyde-m6-2"), capability(payload(host: "mac-mini-m4"))),
            .observe(.hostMismatch)
        )
    }

    func testAppScopeIsEnforced() {
        // Capability minted for T3, prompt observed in ChatGPT.
        XCTAssertEqual(
            evaluate(request(), capability(payload(app: t3))),
            .observe(.appScopeMismatch)
        )
    }

    func testActionScopeIsEnforced() {
        XCTAssertEqual(
            evaluate(
                request(),
                capability(payload(action: "notification-banner-approve"))
            ),
            .observe(.actionScopeMismatch)
        )
    }

    func testPromptScopeIsEnforced() {
        XCTAssertEqual(
            evaluate(request(), capability(payload(fingerprint: "another prompt"))),
            .observe(.promptScopeMismatch)
        )
    }

    // MARK: - one use

    func testValidCapabilityAuthorisesOnceAndOnlyOnce() {
        let ledger = InMemoryNativeGuiReplayLedger()
        let envelope = capability(payload())
        let first = evaluate(request(), envelope, ledger: ledger)
        XCTAssertTrue(first.isAuthorized)
        XCTAssertEqual(first, .press(NativeGuiContainment.AuthorizedAction(
            channel: .systemDialog,
            capabilityNonce: "0123456789abcdef0123456789abcdef",
            taskID: "task-1",
            appBundleID: "com.openai.codex"
        )))
        XCTAssertEqual(
            evaluate(request(), envelope, ledger: ledger),
            .observe(.replayedCapability)
        )
    }

    func testADenialDoesNotConsumeTheNonce() {
        let ledger = InMemoryNativeGuiReplayLedger()
        let envelope = capability(payload())
        // Wrong task: refused before the ledger is touched.
        XCTAssertEqual(
            evaluate(request(taskID: "task-2"), envelope, ledger: ledger),
            .observe(.taskMismatch)
        )
        // The same capability still works for the right task.
        XCTAssertTrue(evaluate(request(), envelope, ledger: ledger).isAuthorized)
    }

    func testConcurrentPresentationOfOneNonceHasOneWinner() {
        let ledger = InMemoryNativeGuiReplayLedger()
        let envelope = capability(payload())
        let decisions = (0..<8).map { _ in
            NativeGuiContainment.evaluate(
                request: request(),
                capability: envelope,
                trustedIssuerSHA256: trusted(),
                replayLedger: ledger,
                now: now
            )
        }
        XCTAssertEqual(decisions.filter(\.isAuthorized).count, 1)
    }

    // MARK: - baseline policy and canonical encoding

    func testBaselineNeverApproveIsNonEmptyAndDeduplicated() {
        XCTAssertFalse(NativeGuiContainment.baselineNeverApprove.isEmpty)
        let effective = NativeGuiContainment.effectiveNeverApprove(["password", "my-own"])
        XCTAssertEqual(effective.filter { $0 == "password" }.count, 1)
        XCTAssertTrue(effective.contains("my-own"))
        XCTAssertTrue(effective.contains("full disk access"))
    }

    func testCanonicalPayloadIsSortedAndStable() {
        let canonical = payload().canonicalJSON()
        XCTAssertTrue(canonical.hasPrefix("{\"Action\":\"system-dialog-approve\","))
        XCTAssertTrue(canonical.hasSuffix("\"Task_Id\":\"task-1\"}"))
        XCTAssertFalse(canonical.contains("\": \""))
        XCTAssertFalse(canonical.contains(", "))
        XCTAssertEqual(payload().canonicalJSON(), canonical)
    }

    func testCapabilityDecodingRejectsUnknownKeys() {
        let envelope = capability(payload())
        let object: [String: Any] = [
            "Schema": envelope.schema,
            "Algorithm": envelope.algorithm,
            "Payload": [
                "Domain": envelope.payload.domain,
                "Purpose": envelope.payload.purpose,
                "Host": envelope.payload.host,
                "Task_Id": envelope.payload.taskID,
                "Session_Id": envelope.payload.sessionID,
                "Request_Id": envelope.payload.requestID,
                "App_Bundle_Id": envelope.payload.appBundleID,
                "App_Team_Id": envelope.payload.appTeamID,
                "App_Requirement_SHA256": envelope.payload.appRequirementSHA256,
                "Action": envelope.payload.action,
                "Prompt_Fingerprint": envelope.payload.promptFingerprint,
                "Nonce": envelope.payload.nonce,
                "Issued_At": envelope.payload.issuedAt,
                "Expires_At": envelope.payload.expiresAt,
                "Unexpected": "field",
            ],
            "Signature": envelope.signatureBase64,
            "Issuer_Public_Key_Pem": envelope.issuerPublicKeyPEM,
        ]
        let data = try! JSONSerialization.data(withJSONObject: object)
        XCTAssertNil(NativeGuiCapabilityEnvelope.decode(data))
    }

    func testSPKIFingerprintMatchesOpenSSLShape() {
        // openssl pkey -pubin -outform DER | sha256sum, for the SPKI of a P-256
        // key: 91 bytes starting 30 59.
        let key = P256.Signing.PrivateKey()
        let pem = key.publicKey.pemRepresentation
        let fingerprint = NativeGuiContainment.spkiSHA256(pem: pem)
        XCTAssertNotNil(fingerprint)
        XCTAssertEqual(fingerprint?.count, 64)
        XCTAssertEqual(fingerprint, NativeGuiContainment.spkiSHA256(pem: pem))
    }
}
