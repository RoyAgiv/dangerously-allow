import Foundation

/// Canonical host identity for durable state keys.
///
/// `ProcessInfo.processInfo.hostName` is reverse-DNS, and on a Mac attached to a
/// tailnet it is not stable: A04 measured `hyde-m6-2.local` ×28,
/// `hyde-m6-2.tail6f7ef3.ts.net` ×7 and `hyde-m6-2` ×5 in 40 consecutive
/// invocations. Anything durable keyed on that spelling would treat the same
/// card as new after a name change, which is the duplicate-press class the
/// card ledger exists to close.
///
/// The canonical form is the **first DNS label, lowercased**:
///
///     hyde-m6-2.local                -> hyde-m6-2
///     hyde-m6-2.tail6f7ef3.ts.net    -> hyde-m6-2
///     Hyde-M6-2.Local.               -> hyde-m6-2
///
/// The rule is deliberately narrow: the first label must be DNS-label shaped
/// (`[a-z0-9]` at the ends, `[a-z0-9-]` inside, at most 63 bytes). A
/// user-visible computer name such as "HYDE M6 2" is skipped, not guessed at,
/// so the resolver can fall through to the BSD hostname. If no candidate yields
/// a label, the result is nil and the caller must refuse; an empty host is
/// already refused by `CardPressIdentity.isComplete` and by the native gate.
///
/// An explicit operator override is not passed through this function: it wins
/// as given, so `--host my.lab.example` stays `my.lab.example`.
public enum HostIdentity {
    public static let maximumLabelLength = 63

    /// The canonical first label of `raw`, or nil when `raw` cannot identify a
    /// host without guessing.
    public static func canonical(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        var name = trimmed
        while name.hasSuffix(".") { name.removeLast() }
        guard !name.isEmpty else { return nil }
        let label = String(name.split(separator: ".", maxSplits: 1,
                                      omittingEmptySubsequences: false)[0])
            .lowercased()
        guard isDNSLabel(label) else { return nil }
        return label
    }

    /// Resolve the first usable candidate in the caller's order. The executable
    /// passes the stable local name first, then the computer name, then the BSD
    /// hostname.
    public static func resolve(from candidates: [String]) -> String? {
        for candidate in candidates {
            if let canonical = canonical(candidate) { return canonical }
        }
        return nil
    }

    public static func isDNSLabel(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximumLabelLength,
              !value.hasPrefix("-"), !value.hasSuffix("-")
        else { return false }
        return value.unicodeScalars.allSatisfy {
            ($0.value >= 97 && $0.value <= 122)
                || ($0.value >= 48 && $0.value <= 57)
                || $0.value == 45
        }
    }
}
