import Foundation
import XCTest
@testable import DangerouslyAllowCore

/// The owner-consent file is the authorization. These tests pin the properties
/// the watcher relies on: a flag alone cannot enable the mode, insecure files
/// are refused, the authentication hard block cannot be removed by the file,
/// and an ordinary app's small dialog is not mistaken for a consent surface.
final class OwnerConsentTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("owner-consent-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func write(_ object: [String: Any], mode: Int = 0o600) throws -> String {
        let url = directory.appendingPathComponent("consent.json")
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        XCTAssertTrue(FileManager.default.createFile(
            atPath: url.path, contents: data,
            attributes: [.posixPermissions: mode]
        ))
        return url.path
    }

    private func validObject() -> [String: Any] {
        [
            "Schema": OwnerConsent.schema,
            "Enabled": true,
            "Allow_Permanent": true,
            "Never_Approve": ["(?i)production"],
        ]
    }

    func testLoadsAnEnabledOwnerFile() throws {
        let consent = try OwnerConsent.load(path: try write(validObject()))
        XCTAssertTrue(consent.allowPermanent)
        XCTAssertEqual(consent.neverApprove, ["(?i)production"])
    }

    func testRefusesAWorldWritableFile() throws {
        let path = try write(validObject(), mode: 0o644)
        XCTAssertThrowsError(try OwnerConsent.load(path: path)) { error in
            XCTAssertEqual(error as? OwnerConsentError, .insecurePermissions(path))
        }
    }

    func testRefusesAnEmptyOrDisabledFile() throws {
        var disabled = validObject()
        disabled["Enabled"] = false
        let path = try write(disabled)
        XCTAssertThrowsError(try OwnerConsent.load(path: path)) { error in
            XCTAssertEqual(error as? OwnerConsentError, .notEnabled(path))
        }
    }

    func testRefusesAnotherSchema() throws {
        var other = validObject()
        other["Schema"] = "somebody-elses-consent/v1"
        let path = try write(other)
        XCTAssertThrowsError(try OwnerConsent.load(path: path))
    }

    func testAuthenticationIsBlockedUnlessTheOwnerEnablesIt() throws {
        let blocked = try OwnerConsent.load(path: try write(validObject()))
            .vetoPatterns(operatorPatterns: [])
        for text in [
            "Enter your password", "Touch ID required", "FileVault is turned on",
            "Keychain access", "sudo wants administrator authentication",
            "Sign in to your Apple Account",
        ] {
            XCTAssertNotNil(
                PromptDetector.blockingPattern(screen: text, neverApprove: blocked),
                "default authentication block missed: \(text)"
            )
        }
        var enabled = validObject()
        enabled["Allow_Authentication"] = true
        let allowed = try OwnerConsent.load(path: try write(enabled))
            .vetoPatterns(operatorPatterns: [])
        for text in ["Enter your password", "Touch ID required", "Keychain access"] {
            XCTAssertNil(PromptDetector.blockingPattern(screen: text, neverApprove: allowed),
                         "owner enabled authentication: \(text)")
        }
        XCTAssertNil(PromptDetector.blockingPattern(
            screen: "node would like to access files in your Documents folder",
            neverApprove: blocked
        ))
    }

    func testDestructiveConfirmationsStayBlockedByDefault() throws {
        var enabled = validObject()
        enabled["Allow_Authentication"] = true
        let consent = try OwnerConsent.load(path: try write(enabled))
        let patterns = consent.vetoPatterns(operatorPatterns: [])
        XCTAssertNotNil(PromptDetector.blockingPattern(
            screen: "Erase All Content and Settings", neverApprove: patterns))
        XCTAssertNotNil(PromptDetector.blockingPattern(
            screen: "Delete this volume?", neverApprove: patterns))
        enabled["Allow_Destructive"] = true
        let lifted = try OwnerConsent.load(path: try write(enabled))
            .vetoPatterns(operatorPatterns: [])
        XCTAssertNil(PromptDetector.blockingPattern(
            screen: "Delete this volume?", neverApprove: lifted))
        // Whole-machine destruction is never lifted, even with the broad flag.
        for text in ["Erase All Content and Settings", "Factory reset",
                     "Reinstall macOS", "Erase this Mac"] {
            XCTAssertNotNil(PromptDetector.blockingPattern(screen: text, neverApprove: lifted),
                            "catastrophic block missed: \(text)")
        }
    }

    func testSystemHostDialogIsAConsentSurface() {
        let dialog = DetectedSystemDialog(
            options: [
                SystemDialogOption(id: 1, label: "Don’t Allow", kind: .deny),
                SystemDialogOption(id: 2, label: "Allow", kind: .allowAlways),
            ],
            target: SystemDialogOption(id: 2, label: "Allow", kind: .allowAlways),
            dialogText: "“node” would like to access files in your Documents folder.",
            fullText: "…",
            fingerprint: "f"
        )
        XCTAssertTrue(OwnerConsent.isConsentDialog(
            dialog: dialog, bundleID: "com.apple.UserNotificationCenter", triggerRecognized: false
        ))
    }

    func testAuthenticationSheetInsideAWindowIsDetected() {
        let field = UINode(id: 1, role: "AXTextField")
        let button = UINode(id: 2, role: "AXButton", label: "Change Password")
        let sheet = UINode(id: 3, role: "AXSheet", children: [field, button])
        let root = UINode(id: 4, role: "AXWindow", children: [sheet])
        guard case let .dialog(dialog)? = SystemDialogDetector.detectSheet(
            root: root, policy: .always) else {
            return XCTFail("sheet not detected")
        }
        XCTAssertEqual(dialog.fields, [1])
        XCTAssertEqual(dialog.target?.label, "Change Password")
    }

    func testPasswordsOnlyGoToSystemAuthenticationSurfaces() {
        XCTAssertTrue(OwnerConsent.isTrustedSecretDialog(
            bundleID: "com.apple.SecurityAgent",
            text: "Enter your password to make changes."))
        XCTAssertTrue(OwnerConsent.isTrustedSecretDialog(
            bundleID: "com.apple.UserNotificationCenter",
            text: "Administrator authentication required"))
        // A fabricated dialog owned by an ordinary app is never filled.
        XCTAssertFalse(OwnerConsent.isTrustedSecretDialog(
            bundleID: "com.apple.osascript",
            text: "Enter your password"))
        XCTAssertFalse(OwnerConsent.isTrustedSecretDialog(
            bundleID: "com.example.app",
            text: "Enter your password"))
        // A trusted surface without authentication wording is not a password prompt.
        XCTAssertFalse(OwnerConsent.isTrustedSecretDialog(
            bundleID: "com.apple.UserNotificationCenter",
            text: "node would like to access your Documents folder"))
    }

    func testAnUnrecognisedAppDialogIsNotAConsentSurface() {
        let dialog = DetectedSystemDialog(
            options: [
                SystemDialogOption(id: 1, label: "Cancel", kind: .deny),
                SystemDialogOption(id: 2, label: "OK", kind: .allowAlways),
            ],
            target: SystemDialogOption(id: 2, label: "OK", kind: .allowAlways),
            dialogText: "Save changes before closing?",
            fullText: "Save changes before closing? Cancel OK",
            fingerprint: "f"
        )
        XCTAssertFalse(OwnerConsent.isConsentDialog(
            dialog: dialog, bundleID: "com.example.app", triggerRecognized: false
        ))
    }
}
