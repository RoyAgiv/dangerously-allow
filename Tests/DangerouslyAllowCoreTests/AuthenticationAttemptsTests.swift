import Foundation
import XCTest
@testable import DangerouslyAllowCore

/// Failed authentication must stop, not loop. The watcher polls continuously,
/// so a rejected credential on a sheet that stays up used to be pressed again
/// every second, indefinitely. These tests pin the bound and its reset rules.
final class AuthenticationAttemptsTests: XCTestCase {
    func testAllowsTheConfiguredNumberOfAttemptsThenRefuses() {
        var attempts = AuthenticationAttempts(limit: 3, window: 120)
        let start = Date(timeIntervalSince1970: 1_000)
        for index in 1...3 {
            XCTAssertTrue(attempts.allow("System Settings\u{a7}Modify Settings|Cancel",
                                         now: start.addingTimeInterval(Double(index))),
                          "attempt \(index) must be allowed")
        }
        XCTAssertFalse(attempts.allow("System Settings\u{a7}Modify Settings|Cancel",
                                      now: start.addingTimeInterval(5)),
                       "the fourth attempt must be refused")
    }

    func testSeparateSurfacesHaveSeparateBudgets() {
        var attempts = AuthenticationAttempts(limit: 1, window: 120)
        let now = Date(timeIntervalSince1970: 2_000)
        XCTAssertTrue(attempts.allow("System Settings\u{a7}Use Password…|Cancel", now: now))
        XCTAssertFalse(attempts.allow("System Settings\u{a7}Use Password…|Cancel", now: now))
        XCTAssertTrue(attempts.allow("System Settings\u{a7}Modify Settings|Cancel", now: now),
                      "a different surface starts with a fresh budget")
    }

    func testTheWindowResetsTheBudget() {
        var attempts = AuthenticationAttempts(limit: 2, window: 120)
        let start = Date(timeIntervalSince1970: 3_000)
        XCTAssertTrue(attempts.allow("k", now: start))
        XCTAssertTrue(attempts.allow("k", now: start.addingTimeInterval(1)))
        XCTAssertFalse(attempts.allow("k", now: start.addingTimeInterval(2)))
        XCTAssertTrue(attempts.allow("k", now: start.addingTimeInterval(123)),
                      "a later prompt is not blocked by an old failure")
    }

    func testDisappearedSurfacesLoseTheirCounters() {
        var attempts = AuthenticationAttempts(limit: 1, window: 120)
        let now = Date(timeIntervalSince1970: 4_000)
        XCTAssertTrue(attempts.allow("old", now: now))
        attempts.keepOnly(["current"])
        XCTAssertTrue(attempts.allow("old", now: now),
                      "a prompt that left the screen starts fresh when it returns")
    }

    func testResetForgetsOneOrEverySurface() {
        var attempts = AuthenticationAttempts(limit: 1, window: 120)
        let now = Date(timeIntervalSince1970: 5_000)
        XCTAssertTrue(attempts.allow("a", now: now))
        XCTAssertTrue(attempts.allow("b", now: now))
        attempts.reset("a")
        XCTAssertTrue(attempts.allow("a", now: now))
        XCTAssertFalse(attempts.allow("b", now: now))
        attempts.reset()
        XCTAssertTrue(attempts.allow("b", now: now))
    }
}
