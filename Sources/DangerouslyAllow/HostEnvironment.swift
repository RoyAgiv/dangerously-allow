import DangerouslyAllowCore
import Foundation
import SystemConfiguration

/// The host's stable local name, in the order macOS actually keeps it.
///
/// `ProcessInfo.processInfo.hostName` is deliberately not consulted: it is
/// reverse-DNS and changes with the network (A04 observed three spellings on
/// one host), so it cannot key durable state. `SCDynamicStoreCopyLocalHostName`
/// is the Bonjour local name (`hyde-m6-2`), which survives restarts, reboots and
/// tailnet changes; the user-visible computer name and the BSD hostname are
/// fallbacks only. `HostIdentity.resolve` applies the documented first-label
/// rule and returns nil when nothing is usable, which becomes the empty host
/// that both the card guard and the native gate refuse.
enum HostEnvironment {
    static func resolvedHost() -> String {
        var candidates: [String] = []
        if let local = SCDynamicStoreCopyLocalHostName(nil) as String? {
            candidates.append(local)
        }
        if let computer = SCDynamicStoreCopyComputerName(nil, nil) as String? {
            candidates.append(computer)
        }
        candidates.append(posixHostName())
        return HostIdentity.resolve(from: candidates) ?? ""
    }

    private static func posixHostName() -> String {
        var buffer = [CChar](repeating: 0, count: 256)
        guard gethostname(&buffer, buffer.count) == 0 else { return "" }
        return String(cString: buffer)
    }
}
