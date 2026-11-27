import Foundation
import XCTest
@testable import DangerouslyAllowCore

/// A04 found the default identity wiring defect: `ProcessInfo.hostName` is
/// reverse-DNS and returns `hyde-m6-2`, `hyde-m6-2.local` and
/// `hyde-m6-2.tail6f7ef3.ts.net` on the same machine, so the same card hashed
/// to different ledger keys across restarts and could be pressed twice. These
/// tests pin the canonical rule that closes that gap.
final class HostIdentityTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func identity(host: String) -> CardPressIdentity {
        CardPressIdentity(
            host: host,
            appBundleID: "com.openai.codex",
            appTeamID: "2DC432GLL2",
            windowIdentity: "ax-id:chatgpt-card-window",
            promptFingerprint: "Allow|Deny\u{a7}Run the tests"
        )
    }

    // MARK: - the observed spellings

    func testTheObservedSpellingsCanonicaliseToOneHost() {
        let spellings = [
            "hyde-m6-2.local",
            "hyde-m6-2.tail6f7ef3.ts.net",
            "hyde-m6-2",
            "Hyde-M6-2.Local.",
            "  hyde-m6-2.local  ",
        ]
        let canonicals = spellings.compactMap(HostIdentity.canonical)
        XCTAssertEqual(canonicals.count, spellings.count)
        XCTAssertEqual(Set(canonicals).count, 1)
        XCTAssertEqual(canonicals.first, "hyde-m6-2")
    }

    func testRawSpellingsWouldBeDifferentLedgerKeys() {
        // Without the canonical default, the defect is real: three spellings,
        // three identities, and a re-presented card looks new to each of them.
        let raw = ["hyde-m6-2.local", "hyde-m6-2.tail6f7ef3.ts.net", "hyde-m6-2"]
        let keys = Set(raw.map { identity(host: $0).ledgerKey })
        XCTAssertEqual(keys.count, 3)
    }

    func testCanonicalSpellingsShareOneClaim() {
        let ledger = InMemoryCardPressLedger()
        let first = identity(host: HostIdentity.canonical("hyde-m6-2.local")!)
        let second = identity(host: HostIdentity.canonical("hyde-m6-2.tail6f7ef3.ts.net")!)
        let third = identity(host: HostIdentity.canonical("hyde-m6-2")!)

        XCTAssertEqual(first.ledgerKey, second.ledgerKey)
        XCTAssertEqual(second.ledgerKey, third.ledgerKey)
        XCTAssertTrue(CardPressGuard.claim(first, ledger: ledger, now: now).isAuthorized)
        XCTAssertEqual(
            CardPressGuard.claim(second, ledger: ledger, now: now.addingTimeInterval(1)).reason,
            "duplicate_card_press"
        )
        XCTAssertEqual(
            CardPressGuard.claim(third, ledger: ledger, now: now.addingTimeInterval(2)).reason,
            "duplicate_card_press"
        )
        XCTAssertEqual(ledger.liveClaimCount, 1)
    }

    // MARK: - explicit override and refusal

    func testExplicitOverrideIsPreservedNotRewritten() {
        // The executable applies canonicalisation only to the *default*. An
        // operator who pins --host gets exactly the string they asked for.
        let override = identity(host: "my.lab.example")
        XCTAssertEqual(override.host, "my.lab.example")
        XCTAssertNotEqual(override.ledgerKey, identity(host: "my").ledgerKey)
    }

    func testUndeterminableHostIsNil() {
        XCTAssertNil(HostIdentity.resolve(from: []))
        XCTAssertNil(HostIdentity.resolve(from: [
            "", "   ", "\n", "HYDE M6 2", "-leading", "trailing-", "under_score",
            "colon:name", "é", String(repeating: "a", count: 64),
        ]))
    }

    func testUndeterminableHostRefusesTheCard() {
        let ledger = InMemoryCardPressLedger()
        let decision = CardPressGuard.claim(identity(host: ""), ledger: ledger, now: now)
        XCTAssertFalse(decision.isAuthorized)
        XCTAssertEqual(decision.reason, "incomplete_card_identity")
        XCTAssertEqual(ledger.liveClaimCount, 0)
    }

    func testResolverSkipsInvalidCandidatesAndKeepsOrder() {
        XCTAssertEqual(
            HostIdentity.resolve(from: ["HYDE M6 2", "hyde-m6-2.local", "other-host"]),
            "hyde-m6-2"
        )
        XCTAssertEqual(
            HostIdentity.resolve(from: ["first-host", "second-host"]),
            "first-host"
        )
    }

    // MARK: - the rule itself

    func testCanonicalisationIsIdempotentAndCaseInsensitive() {
        let once = HostIdentity.canonical("Hyde-M6-2.Tail6F7EF3.TS.NET")!
        XCTAssertEqual(once, "hyde-m6-2")
        XCTAssertEqual(HostIdentity.canonical(once), once)
    }

    func testSingleLabelAndTrailingDots() {
        XCTAssertEqual(HostIdentity.canonical("hyde-m6-2"), "hyde-m6-2")
        XCTAssertEqual(HostIdentity.canonical("hyde-m6-2..."), "hyde-m6-2")
        XCTAssertEqual(HostIdentity.canonical("a.b.c"), "a")
        XCTAssertNil(HostIdentity.canonical("..."))
    }

    func testInvalidLabelsAreRejected() {
        XCTAssertNil(HostIdentity.canonical("-bad"))
        XCTAssertNil(HostIdentity.canonical("bad-"))
        XCTAssertNil(HostIdentity.canonical("bad_name"))
        XCTAssertNil(HostIdentity.canonical("bad name"))
        XCTAssertNil(HostIdentity.canonical(String(repeating: "a", count: 64)))
        XCTAssertTrue(HostIdentity.isDNSLabel("hyde-m6-2"))
    }
}
