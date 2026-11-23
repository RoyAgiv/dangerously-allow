import DangerouslyAllowCore
import Foundation

/// File-backed one-shot card ledger, the durable half of `CardPressGuard`.
///
/// One file per claimed card identity, named by the SHA-256 of its canonical
/// key. `O_CREAT|O_EXCL` is the atomic bit: any number of watcher processes
/// presenting the same card race to create the same file, and exactly one wins.
/// Any I/O error returns `.unavailable`, which the guard turns into a refusal —
/// a broken ledger never authorises a press.
///
/// Retention is bounded twice: each record carries `Expires_At` and expired
/// records are pruned before a claim, and a hard cap on live records makes a
/// full store fail closed rather than grow without limit. Claims are never
/// evicted early to make room; an evicted claim would let a re-presented card be
/// pressed again, which is the thing this exists to prevent.
final class FileCardPressLedger: CardPressClaimRecording {
    /// Enough for a year of one-per-minute cards; a store that reaches this is
    /// a signal (a stuck app re-presenting forever), not a normal state.
    static let maximumEntries = 4096

    private let directory: URL
    private let retention: TimeInterval

    init(directory: URL, retention: TimeInterval = CardPressGuard.defaultRetention) {
        self.directory = directory
        self.retention = retention
    }

    static func defaultDirectory() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("dangerously-allow/card-press-ledger", isDirectory: true)
    }

    func claim(_ identity: CardPressIdentity, now: Date) -> CardClaimOutcome {
        let manager = FileManager.default
        do {
            try manager.createDirectory(
                at: directory, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            return .unavailable
        }

        pruneExpired(now: now)
        guard liveEntryCount() < Self.maximumEntries else { return .unavailable }

        // Encode before creating the file: a failure here must not burn a claim
        // on a record that cannot be read back.
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        let record: [String: Any] = [
            "Schema": "dangerously-allow-card-press-claim/v1",
            "Card_Press_Key": identity.ledgerKey,
            "Host": identity.host,
            "App_Bundle_Id": identity.appBundleID,
            "App_Team_Id": identity.appTeamID,
            "Window_Identity": identity.windowIdentity,
            "Prompt_Fingerprint": identity.promptFingerprint,
            "Claimed_At": formatter.string(from: now),
            "Expires_At": formatter.string(from: now.addingTimeInterval(retention)),
        ]
        guard let data = try? JSONSerialization.data(
            withJSONObject: record, options: [.sortedKeys]
        ) else { return .unavailable }

        let path = directory.appendingPathComponent(identity.ledgerKey + ".json")
        let descriptor = open(path.path, O_CREAT | O_EXCL | O_WRONLY, 0o600)
        guard descriptor >= 0 else {
            return errno == EEXIST ? .duplicate : .unavailable
        }
        defer { close(descriptor) }

        let written = data.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return write(descriptor, base, buffer.count)
        }
        guard written == data.count else {
            // The file exists, so this claim is spent either way; remove the
            // partial record and refuse, rather than leaving a card pressable.
            try? manager.removeItem(at: path)
            return .unavailable
        }
        return .claimed
    }

    /// Expired records go; malformed ones stay until they age out, because a
    /// malformed record may be a claim whose write was interrupted and the safe
    /// reading of it is "already claimed".
    private func pruneExpired(now: Date) {
        let manager = FileManager.default
        guard let entries = try? manager.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: [.contentModificationDateKey]
        ) else { return }
        let parser = ISO8601DateFormatter()
        parser.formatOptions = [.withInternetDateTime]
        for entry in entries where entry.pathExtension == "json" {
            if let data = try? Data(contentsOf: entry),
               let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let raw = object["Expires_At"] as? String,
               let expires = parser.date(from: raw) {
                if expires <= now { try? manager.removeItem(at: entry) }
                continue
            }
            let modified = (try? entry.resourceValues(forKeys: [.contentModificationDateKey]))?
                .contentModificationDate
            if let modified, modified.addingTimeInterval(retention) <= now {
                try? manager.removeItem(at: entry)
            }
        }
    }

    private func liveEntryCount() -> Int {
        (try? FileManager.default.contentsOfDirectory(
            at: directory, includingPropertiesForKeys: nil
        ))?.filter { $0.pathExtension == "json" }.count ?? Int.max
    }
}
