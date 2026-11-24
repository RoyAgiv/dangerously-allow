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

    func testTheAuthHardBlockCannotBeRemoved() throws {
        let consent = try OwnerConsent.load(path: try write(validObject()))
        let patterns = consent.vetoPatterns(operatorPatterns: [])
        for text in [
            "Enter your password", "Touch ID required", "FileVault is turned on",
            "Keychain access", "sudo wants administrator authentication",
            "Sign in to your Apple Account",
        ] {
            XCTAssertNotNil(
                PromptDetector.blockingPattern(screen: text, neverApprove: patterns),
                "hard block missed: \(text)"
            )
        }
        XCTAssertNil(PromptDetector.blockingPattern(
            screen: "node would like to access files in your Documents folder",
            neverApprove: patterns
        ))
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
