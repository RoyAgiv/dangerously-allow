import Foundation

/// A durable, one-shot claim on one *presentation* of an approval card.
///
/// The native-GUI channel already spends a capability nonce exactly once, but
/// an in-app approval card has no nonce: it is just a subtree of an app's
/// Accessibility tree. A04 found the gap that leaves: two presentations of the
/// same card produced two physical presses while the operation deduplicated
/// once. The in-memory `handled` set only suppresses a card while it is still
/// on screen, so a card that is re-presented — after the app redraws it, from a
/// second window, from another watcher process, or after the watcher restarts —
/// looks new again.
///
/// This is the press-level guard. It is keyed on stable identity material, not
/// on the transient AX element id:
///
///  * the host the watcher runs on,
///  * the app's signed identity (bundle id and team id),
///  * a window/card identity that survives rescans of the same window, and
///  * the card's own prompt fingerprint (option labels plus card wording).
///
/// A re-presented identical card hashes to the same key and is refused with
/// `duplicate_card_press`; a genuinely new card carries different wording, a
/// different command, or a different window and is still pressable. The claim
/// is written with `O_CREAT|O_EXCL` so only one of any number of concurrent
/// processes can win, and it is retained for a bounded time so the ledger
/// cannot grow forever.
///
/// Deliberately absent: anything the card says about itself. A card cannot
/// assert its own identity, and `Task_Id`/`Session_Id` are not part of the key
/// — they are correlators, never authorisation.
public struct CardPressIdentity: Equatable, Hashable {
    /// Longest accepted value for any one identity field. Real window titles,
    /// bundle ids and card fingerprints are far shorter; a longer value is a
    /// reason to refuse, not to truncate (truncation could merge two cards).
    public static let maximumFieldLength = 512

    public let host: String
    public let appBundleID: String
    public let appTeamID: String
    public let windowIdentity: String
    public let promptFingerprint: String

    public init(
        host: String,
        appBundleID: String,
        appTeamID: String = "",
        windowIdentity: String,
        promptFingerprint: String
    ) {
        self.host = host
        self.appBundleID = appBundleID
        self.appTeamID = appTeamID
        self.windowIdentity = windowIdentity
        self.promptFingerprint = promptFingerprint
    }

    /// The fields that must identify *something*. The team id is allowed to be
    /// empty: a notification banner has no attestable poster, and the card
    /// channel can see an app before its signature probe has a team.
    public var isComplete: Bool {
        let required = [host, appBundleID, windowIdentity, promptFingerprint]
        guard required.allSatisfy({
            !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }) else { return false }
        return allFields.allSatisfy { $0.count <= Self.maximumFieldLength }
    }

    /// Length-prefixed so no value can masquerade as two fields or absorb a
    /// separator: `3:foo|0:|3:bar` is unambiguous even when a field contains
    /// `|`, `:`, a newline, or nothing at all.
    public var canonicalKey: String {
        allFields.map { "\($0.utf8.count):\($0)" }.joined(separator: "|")
    }

    /// SHA-256 of `canonicalKey`; the filename the durable ledger claims.
    public var ledgerKey: String {
        NativeGuiContainment.sha256Hex(canonicalKey)
    }

    private var allFields: [String] {
        [host, appBundleID, appTeamID, windowIdentity, promptFingerprint]
    }
}

/// What a ledger did with a claim. `unavailable` is not a duplicate: it means
/// the store could not be read or written, and the only safe answer is not to
/// press.
public enum CardClaimOutcome: String, Equatable, CaseIterable {
    case claimed
    case duplicate
    case unavailable
}

/// The durable side of the guard. `claim` must be atomic across processes:
/// exactly one caller may observe `.claimed` for one identity per retention
/// window.
public protocol CardPressClaimRecording: AnyObject {
    func claim(_ identity: CardPressIdentity, now: Date) -> CardClaimOutcome
}

/// Why a card press was not authorised. `duplicate_card_press` is the distinct
/// code for a re-presented card; the others make a broken store or an
/// unidentifiable card equally visible instead of silently pressing.
public enum CardPressRefusal: String, Equatable, CaseIterable {
    case incompleteCardIdentity = "incomplete_card_identity"
    case cardLedgerUnavailable = "card_ledger_unavailable"
}

public enum CardPressDecision: Equatable {
    case press(CardPressIdentity)
    case duplicate(CardPressIdentity)
    case refused(CardPressRefusal)

    /// True only for the single claim that may become a physical press.
    public var isAuthorized: Bool {
        if case .press = self { return true }
        return false
    }

    public var isDuplicate: Bool {
        if case .duplicate = self { return true }
        return false
    }

    public var reason: String {
        switch self {
        case .press: return "authorized"
        case .duplicate: return "duplicate_card_press"
        case let .refused(refusal): return refusal.rawValue
        }
    }

    public var identity: CardPressIdentity? {
        switch self {
        case let .press(identity), let .duplicate(identity): return identity
        case .refused: return nil
        }
    }
}

public enum CardPressGuard {
    /// How long one claim suppresses re-presentations of the same card. A card
    /// that is still being re-presented a day later is not a prompt a watcher
    /// should answer unattended; a human owns it after this.
    public static let defaultRetention: TimeInterval = 24 * 60 * 60

    /// The one decision point the watchers use. It refuses an unidentifiable
    /// card before touching the store, so an empty window identity can never
    /// collapse every card in an app onto one ledger entry.
    public static func claim(
        _ identity: CardPressIdentity,
        ledger: CardPressClaimRecording,
        now: Date = Date()
    ) -> CardPressDecision {
        guard identity.isComplete else { return .refused(.incompleteCardIdentity) }
        switch ledger.claim(identity, now: now) {
        case .claimed: return .press(identity)
        case .duplicate: return .duplicate(identity)
        case .unavailable: return .refused(.cardLedgerUnavailable)
        }
    }
}

/// In-memory ledger for unit tests and diagnostics. The executable uses the
/// file-backed ledger; this one exists so the guard's contract can be pinned
/// without touching the disk.
public final class InMemoryCardPressLedger: CardPressClaimRecording {
    private var claims: [String: Date] = [:]
    private let retention: TimeInterval

    public init(retention: TimeInterval = CardPressGuard.defaultRetention) {
        self.retention = retention
    }

    public func claim(_ identity: CardPressIdentity, now: Date) -> CardClaimOutcome {
        claims = claims.filter { $0.value > now }
        let key = identity.ledgerKey
        guard claims[key] == nil else { return .duplicate }
        claims[key] = now.addingTimeInterval(retention)
        return .claimed
    }

    /// Number of live claims, for tests that assert retention is bounded.
    public var liveClaimCount: Int { claims.count }
}
