import Foundation
import XCTest
@testable import DangerouslyAllowCore

/// The press-level card ledger's contract. A04 showed that operation-level
/// dedup was not press-level dedup: the same approval card, presented twice,
/// produced two physical presses. These tests pin the replacement: one durable
/// claim per (host, signed app, window, prompt), a distinct denial for a
/// re-presentation, and a genuinely new card still pressable.
final class CardPressLedgerTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func identity(
        host: String = "hyde-m6-2",
        bundle: String = "com.openai.codex",
        team: String = "2DC432GLL2",
        window: String = "ax-id:chatgpt-card-window",
        prompt: String = "Allow|Deny\u{a7}Run the tests"
    ) -> CardPressIdentity {
        CardPressIdentity(
            host: host, appBundleID: bundle, appTeamID: team,
            windowIdentity: window, promptFingerprint: prompt
        )
    }

    private final class UnavailableLedger: CardPressClaimRecording {
        func claim(_ identity: CardPressIdentity, now: Date) -> CardClaimOutcome { .unavailable }
    }

    // MARK: - the A04 gap

    func testTheSamePresentationPressesExactlyOnce() {
        let ledger = InMemoryCardPressLedger()
        let first = CardPressGuard.claim(identity(), ledger: ledger, now: now)
        XCTAssertTrue(first.isAuthorized)
        XCTAssertEqual(first.reason, "authorized")
        XCTAssertFalse(first.isDuplicate)

        let second = CardPressGuard.claim(
            identity(), ledger: ledger, now: now.addingTimeInterval(0.5)
        )
        XCTAssertFalse(second.isAuthorized)
        XCTAssertTrue(second.isDuplicate)
        XCTAssertEqual(second.reason, "duplicate_card_press")
        XCTAssertEqual(ledger.liveClaimCount, 1)
    }

    func testAReplayLongAfterTheClaimIsStillADuplicate() {
        let ledger = InMemoryCardPressLedger()
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
        let replay = CardPressGuard.claim(
            identity(), ledger: ledger, now: now.addingTimeInterval(6 * 3600)
        )
        XCTAssertEqual(replay.reason, "duplicate_card_press")
        XCTAssertFalse(replay.isAuthorized)
    }

    func testTheDuplicateCarriesTheSameIdentityItRefused() {
        let ledger = InMemoryCardPressLedger()
        _ = CardPressGuard.claim(identity(), ledger: ledger, now: now)
        let duplicate = CardPressGuard.claim(identity(), ledger: ledger, now: now)
        XCTAssertEqual(duplicate.identity, identity())
    }

    // MARK: - a genuinely new card still works

    func testADifferentPromptIsGenuinelyNew() {
        let ledger = InMemoryCardPressLedger()
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
        let newCard = identity(prompt: "Allow|Deny\u{a7}Run a different command")
        XCTAssertTrue(CardPressGuard.claim(newCard, ledger: ledger, now: now).isAuthorized)
        XCTAssertEqual(ledger.liveClaimCount, 2)
    }

    func testADifferentWindowIsGenuinelyNew() {
        let ledger = InMemoryCardPressLedger()
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
        let otherWindow = identity(window: "ax-id:chatgpt-second-window")
        XCTAssertTrue(CardPressGuard.claim(otherWindow, ledger: ledger, now: now).isAuthorized)
    }

    func testADifferentAppIsGenuinelyNew() {
        let ledger = InMemoryCardPressLedger()
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
        let t3 = identity(bundle: "com.t3tools.t3code", team: "ARK85ZXQ4Z")
        XCTAssertTrue(CardPressGuard.claim(t3, ledger: ledger, now: now).isAuthorized)
    }

    func testADifferentHostIsGenuinelyNew() {
        let ledger = InMemoryCardPressLedger()
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
        XCTAssertTrue(CardPressGuard.claim(
            identity(host: "mac-mini-m4"), ledger: ledger, now: now
        ).isAuthorized)
    }

    func testADifferentTeamIsGenuinelyNew() {
        let ledger = InMemoryCardPressLedger()
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
        XCTAssertTrue(CardPressGuard.claim(
            identity(team: "ARK85ZXQ4Z"), ledger: ledger, now: now
        ).isAuthorized)
    }

    // MARK: - identity material

    func testIncompleteIdentityIsRefusedAndConsumesNothing() {
        let ledger = InMemoryCardPressLedger()
        let noWindow = CardPressGuard.claim(
            identity(window: "  "), ledger: ledger, now: now
        )
        XCTAssertEqual(noWindow.reason, "incomplete_card_identity")
        XCTAssertFalse(noWindow.isAuthorized)
        XCTAssertNil(noWindow.identity)
        XCTAssertEqual(ledger.liveClaimCount, 0)

        // The refusal must not have burned the real card's claim.
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
    }

    func testEmptyAppOrPromptIsRefused() {
        let ledger = InMemoryCardPressLedger()
        XCTAssertEqual(
            CardPressGuard.claim(identity(bundle: ""), ledger: ledger, now: now).reason,
            "incomplete_card_identity"
        )
        XCTAssertEqual(
            CardPressGuard.claim(identity(prompt: ""), ledger: ledger, now: now).reason,
            "incomplete_card_identity"
        )
        XCTAssertEqual(
            CardPressGuard.claim(identity(host: ""), ledger: ledger, now: now).reason,
            "incomplete_card_identity"
        )
        XCTAssertEqual(ledger.liveClaimCount, 0)
    }

    func testOverlongFieldIsRefusedNotTruncated() {
        let ledger = InMemoryCardPressLedger()
        let overlong = identity(prompt: String(repeating: "a", count: 513))
        XCTAssertEqual(
            CardPressGuard.claim(overlong, ledger: ledger, now: now).reason,
            "incomplete_card_identity"
        )
    }

    func testMultilineCardTextStillIdentifies() {
        let ledger = InMemoryCardPressLedger()
        let multiline = identity(prompt: "Allow|Deny\u{a7}Run this:\nrm -rf build")
        XCTAssertTrue(multiline.isComplete)
        XCTAssertTrue(CardPressGuard.claim(multiline, ledger: ledger, now: now).isAuthorized)
    }

    func testCanonicalKeyCannotBeForgedByASeparator() {
        let x = CardPressIdentity(
            host: "a", appBundleID: "b", appTeamID: "c",
            windowIdentity: "d", promptFingerprint: "e"
        )
        let y = CardPressIdentity(
            host: "a|1:b", appBundleID: "c", appTeamID: "",
            windowIdentity: "d", promptFingerprint: "e"
        )
        XCTAssertNotEqual(x.canonicalKey, y.canonicalKey)
        XCTAssertNotEqual(x.ledgerKey, y.ledgerKey)
    }

    func testLedgerKeyIsAStableSHA256() {
        let key = identity().ledgerKey
        XCTAssertEqual(key.count, 64)
        XCTAssertEqual(key, identity().ledgerKey)
        XCTAssertNotEqual(key, identity(prompt: "Allow|Deny\u{a7}other").ledgerKey)
    }

    // MARK: - retention and failure

    func testRetentionExpiresTheClaim() {
        let ledger = InMemoryCardPressLedger(retention: 60)
        XCTAssertTrue(CardPressGuard.claim(identity(), ledger: ledger, now: now).isAuthorized)
        XCTAssertEqual(
            CardPressGuard.claim(identity(), ledger: ledger, now: now.addingTimeInterval(59)).reason,
            "duplicate_card_press"
        )
        XCTAssertTrue(
            CardPressGuard.claim(identity(), ledger: ledger, now: now.addingTimeInterval(60)).isAuthorized
        )
    }

    func testExpiredClaimsArePruned() {
        let ledger = InMemoryCardPressLedger(retention: 60)
        _ = CardPressGuard.claim(identity(), ledger: ledger, now: now)
        _ = CardPressGuard.claim(
            identity(prompt: "other"), ledger: ledger, now: now.addingTimeInterval(120)
        )
        XCTAssertEqual(ledger.liveClaimCount, 1)
    }

    func testAnUnavailableLedgerRefusesInsteadOfPressing() {
        let decision = CardPressGuard.claim(
            identity(), ledger: UnavailableLedger(), now: now
        )
        XCTAssertFalse(decision.isAuthorized)
        XCTAssertEqual(decision.reason, "card_ledger_unavailable")
        XCTAssertEqual(CardPressRefusal.cardLedgerUnavailable.rawValue, "card_ledger_unavailable")
    }
}
