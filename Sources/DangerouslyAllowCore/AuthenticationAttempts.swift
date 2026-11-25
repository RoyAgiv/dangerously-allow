import Foundation

/// Bounds repeated presses on one authentication surface.
///
/// An authentication sheet that keeps coming back means the credential, the
/// field or the whole layout was rejected. Pressing it again cannot fix that,
/// and the watcher polls continuously, so an unbounded retry is a loop that
/// runs until a human notices. The surface is identified by the app and its
/// buttons rather than by wording, because wording is exactly what changes
/// when macOS reports an error ("Try again") or a field value is typed.
///
/// The window keeps a long-running watcher from refusing a later, legitimate
/// prompt because of an old failure.
public struct AuthenticationAttempts {
    public static let defaultLimit = 3
    public static let defaultWindow: TimeInterval = 120

    public let limit: Int
    public let window: TimeInterval
    private var attempts: [String: (count: Int, at: Date)] = [:]

    public init(limit: Int = AuthenticationAttempts.defaultLimit,
                window: TimeInterval = AuthenticationAttempts.defaultWindow) {
        self.limit = limit
        self.window = window
    }

    /// Records one attempt and reports whether it may proceed. The first
    /// `limit` attempts in a window are allowed; later ones are refused.
    public mutating func allow(_ key: String, now: Date = Date()) -> Bool {
        var entry = attempts[key] ?? (count: 0, at: now)
        if now.timeIntervalSince(entry.at) > window { entry.count = 0 }
        entry.count += 1
        entry.at = now
        attempts[key] = entry
        return entry.count <= limit
    }

    /// Forgets one surface, or every surface, after a confirmed success or a
    /// deliberate reset.
    public mutating func reset(_ key: String? = nil) {
        if let key { attempts.removeValue(forKey: key) } else { attempts.removeAll() }
    }

    /// Drops counters for surfaces that are no longer on screen. A prompt that
    /// disappeared is not the one that is failing, so a later prompt starts
    /// with a fresh budget instead of inheriting an old failure.
    public mutating func keepOnly(_ keys: Set<String>) {
        attempts = attempts.filter { keys.contains($0.key) }
    }
}
