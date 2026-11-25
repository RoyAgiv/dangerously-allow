import Foundation

/// One button on a native macOS permission dialog.
public struct SystemDialogOption: Equatable {
    public let id: Int
    public let label: String
    public let kind: OptionKind

    public init(id: Int, label: String, kind: OptionKind) {
        self.id = id
        self.label = label
        self.kind = kind
    }
}

public struct DetectedSystemDialog {
    /// Every labelled button on the dialog, in tree order.
    public let options: [SystemDialogOption]
    /// Text fields on the dialog, in tree order. A password prompt carries one;
    /// a plain consent dialog carries none.
    public let fields: [Int]
    /// The subset of `fields` that are secure entry fields, in tree order.
    /// An administrator sheet offers an account-name field and then a password
    /// field; only the secure one may receive a secret.
    public let secureFields: [Int]
    /// The button the policy allows pressing. nil = this is a real permission
    /// dialog, but nothing on it is acceptable — leave it for a human.
    public let target: SystemDialogOption?
    /// The dialog's own wording, excluding button labels.
    public let dialogText: String
    /// Wording plus button labels; what `--never-approve` vetoes on.
    public let fullText: String
    /// Stable across rescans of the same dialog; ids are deliberately excluded.
    public let fingerprint: String

    public init(
        options: [SystemDialogOption],
        fields: [Int] = [],
        secureFields: [Int] = [],
        target: SystemDialogOption?,
        dialogText: String,
        fullText: String,
        fingerprint: String
    ) {
        self.options = options
        self.fields = fields
        self.secureFields = secureFields
        self.target = target
        self.dialogText = dialogText
        self.fullText = fullText
        self.fingerprint = fingerprint
    }

    /// The one field a secret may be typed into: a secure entry field. A
    /// dialog carrying only a plain field (an account name, a search box) must
    /// never receive a password — that is how "STAR007…" ends up typed over
    /// the administrator's name and the sheet can never be satisfied.
    public var passwordField: Int? { secureFields.first }

    /// A method switch such as "Use Password…" on a Touch ID sheet. It grants
    /// nothing; it only reveals the password fields, so it is pressed as a
    /// preparatory step and never treated as the dialog's grant button.
    public var passwordMethodOption: SystemDialogOption? {
        options.first { SystemDialogDetector.isPasswordMethod($0.label) }
    }
}

/// Why a window was passed over. Surfaced by `--verbose` so an unrecognised
/// dialog can be diagnosed without guessing at the AX tree.
public enum SystemDialogSkip: Equatable {
    /// Nothing to press, or far too much — an app window, not a dialog.
    case notADialog(buttons: Int)
    /// No permission wording anywhere in it.
    case noPermissionWording
    /// Permission wording, but no button that grants anything.
    case noGrant
}

public enum SystemDialogScan {
    case dialog(DetectedSystemDialog)
    case skipped(SystemDialogSkip)
}

/// Finds a native macOS permission dialog — Microphone, Screen Recording,
/// Accessibility, Location — in a window's accessibility tree.
///
/// It is deliberately *not* `ButtonPromptDetector`. That one requires a card to
/// offer both a grant and a refusal, on the grounds that every real permission
/// prompt offers a way out. A system dialog often does not: macOS 15's
/// screen-capture prompt offers "Allow" and "Open System Settings", and the way
/// out is Esc. So the gate here is different — the wording (system-generated,
/// far more reliable than a TUI's), the dialog shape, and a grant tier that
/// tells the truth about how long the grant lasts.
public enum SystemDialogDetector {
    /// A permission dialog carries a handful of buttons. More than this is an
    /// ordinary window that happens to mention a service name.
    static let maxOptions = 5

    /// Wording taken from shipped dialogs, not guessed.
    static let permissionKeywords: [String] = [
        // The classic TCC sentence, unchanged for a decade.
        "would like to access", "would like to use",
        "would like to record", "would like to control",
        "wants to access", "wants to use", "wants to control",
        // Apple Events (Automation), which builds its sentence from a different
        // verb frame and names no service: "“ChatGPT” wants access to control
        // “FastMD”. Allowing control will provide access to documents and data
        // in “FastMD”, and to perform actions within that app."
        "wants access to", "allowing control will",
        // macOS 15 / ScreenCaptureKit, which names neither a verb from the list
        // above nor a service: "…is requesting to bypass the system private
        // window picker and directly access your screen and audio."
        "is requesting to", "is requesting access", "requests access to",
        "private window picker",
        "access your screen", "record your screen", "system audio",
        // Two more that lead with a verb the frames above do not cover.
        "devices on your local network", "send you notifications",
        // Chrome's own remote-debugging dialog, which is not a TCC dialog at
        // all: an app wrote this sentence, so it matches none of the system
        // frames above. "An external app wants full control over this Chrome
        // session to debug it."
        "wants full control", "full control over", "remote debugging",
        // Dialogs that lead with the service name instead of a sentence.
        "microphone", "camera", "screen recording", "accessibility",
        "speech recognition", "input monitoring", "full disk access",
        "automation", "developer tools", "location",
    ]

    /// The only grants on a system dialog that really do expire. Everything
    /// else is written to the TCC database and survives a relaunch — including
    /// "While Using the App", which reads bounded and is not: it is a permanent
    /// entry carrying a usage condition.
    static let boundedGrantPhrases: [String] = ["once", "this time"]

    /// A grant here outlives the process, so it is `.allowAlways` however
    /// mildly its button is worded — a plain "Allow" on a TCC dialog is a
    /// permanent grant, and the default `session` policy declines it.
    public static func classify(_ label: String) -> OptionKind {
        let kind = OptionClassifier.classify(label)
        guard kind.grantsAccess else { return kind }
        let lowered = OptionClassifier.foldApostrophes(label).lowercased()
        if boundedGrantPhrases.contains(where: { lowered.contains($0) }) { return kind }
        return .allowAlways
    }

    /// Wording of the button that swaps a Touch ID prompt for a password sheet.
    /// "Use Touch ID" is deliberately absent: it switches the other way.
    static let passwordMethodPrefixes: [String] = [
        "use password", "use the password", "enter password", "type password",
    ]

    /// True for a method switch such as "Use Password…". It only reveals the
    /// fields of an authentication sheet, so it can be pressed before the
    /// sheet has any text field at all — a Touch ID prompt carries none.
    public static func isPasswordMethod(_ label: String) -> Bool {
        let lowered = OptionClassifier.foldApostrophes(label)
            .lowercased().trimmingCharacters(in: .whitespaces)
        for prefix in passwordMethodPrefixes where lowered.hasPrefix(prefix) {
            // The switch is the whole label, possibly with an ellipsis. A
            // longer label ("Use Password Manager…") is a different action.
            let rest = lowered.dropFirst(prefix.count)
            if rest.isEmpty || rest.allSatisfy({ "….:;· ".contains($0) }) { return true }
        }
        return false
    }

    /// True when the dialog wording matches a shipped permission sentence.
    /// Used both by `--require-trigger` and by the containment gate, which
    /// refuses to press a native dialog whose wording it does not recognise.
    public static func hasRecognizedTrigger(_ text: String) -> Bool {
        let lowered = text.lowercased()
        return permissionKeywords.contains { lowered.contains($0) }
    }

    /// `requireTrigger` gates on the wording list above. The watchers leave it
    /// off: the list is transcribed from dialogs that shipped, so it only ever
    /// knows the past, and every sentence it has not met yet — Chrome's
    /// remote-debugging dialog, the next OS release's rephrasing — is silently
    /// walked past with no trace in the log. Off, the gate that remains is the
    /// shape (a handful of buttons) and the classifier (something on it has to
    /// grant), which is what the policy ceiling was written to stand on.
    public static func detect(
        root: UINode, policy: AllowPolicy, requireTrigger: Bool = false
    ) -> SystemDialogScan {
        var buttons: [UINode] = []
        var texts: [String] = []
        var fields: [Int] = []
        var secureFields: [Int] = []
        collect(root, buttons: &buttons, texts: &texts, fields: &fields,
                secureFields: &secureFields)

        let labelled = buttons.filter { !$0.label.isEmpty }
        guard !labelled.isEmpty, labelled.count <= maxOptions else {
            return .skipped(.notADialog(buttons: labelled.count))
        }

        let dialogText = texts.joined(separator: " ")
        if requireTrigger {
            guard hasRecognizedTrigger(dialogText) else {
                return .skipped(.noPermissionWording)
            }
        }

        let options = labelled.map {
            SystemDialogOption(id: $0.id, label: $0.label, kind: classify($0.label))
        }
        guard options.contains(where: { $0.kind.grantsAccess }) else {
            return .skipped(.noGrant)
        }

        // The policy walks its preference chain — most persistent grant it
        // accepts first — and never escalates past it. Deny and neutral are
        // structurally unreachable: they are in no preference list, which is
        // what keeps "Open System Settings" and "Don't Allow" unpressable.
        let target = policy.preference.lazy
            .compactMap { kind in options.first(where: { $0.kind == kind }) }
            .first

        let labels = options.map(\.label)
        return .dialog(
            DetectedSystemDialog(
                options: options,
                fields: fields,
                secureFields: secureFields,
                target: target,
                dialogText: dialogText,
                fullText: dialogText + " " + labels.joined(separator: " "),
                fingerprint: labels.joined(separator: "|") + "\u{a7}" + dialogText
            )
        )
    }

    /// An authentication sheet lives inside an application window, so the
    /// window as a whole has far too many buttons to be a dialog. Evaluate the
    /// sheet subtree on its own: a small set of buttons, at least one text
    /// field, and one primary action (e.g. "Change Password", "Unlock").
    /// Returns nil when no sheet qualifies, so the caller can fall back to the
    /// ordinary whole-window scan.
    public static func detectSheet(
        root: UINode, policy: AllowPolicy, requireTrigger: Bool = false
    ) -> SystemDialogScan? {
        var result: SystemDialogScan?
        func visit(_ node: UINode) {
            if result != nil { return }
            if node.role == "AXSheet" || node.role == "AXDialog" {
                var buttons: [UINode] = []
                var texts: [String] = []
                var fields: [Int] = []
                var secureFields: [Int] = []
                collect(node, buttons: &buttons, texts: &texts, fields: &fields,
                        secureFields: &secureFields)
                let labelled = buttons.filter { !$0.label.isEmpty }
                // A Touch ID prompt has no text field until its "Use Password…"
                // switch is pressed, so a method switch alone qualifies.
                let methodSheet = fields.isEmpty
                    && labelled.contains { isPasswordMethod($0.label) }
                if !fields.isEmpty || methodSheet, !labelled.isEmpty,
                   labelled.count <= maxOptions {
                    let classified = labelled.map {
                        SystemDialogOption(id: $0.id, label: $0.label, kind: classify($0.label))
                    }
                    // Task-specific sheet buttons ("Change Password", "Unlock")
                    // classify as neutral; the last non-deny action is the
                    // sheet's real primary button. A method switch grants
                    // nothing, so it never borrows the grant tier.
                    var options = classified
                    if !fields.isEmpty,
                       let primary = classified.last(where: { $0.kind != .deny }) {
                        // A sheet's primary button is its grant action even when
                        // its wording is task-specific ("Change Password").
                        options = classified.map {
                            $0.id == primary.id
                                ? SystemDialogOption(id: $0.id, label: $0.label, kind: .allowAlways)
                                : $0
                        }
                    }
                    let dialogText = texts.joined(separator: " ")
                    let lowered = dialogText.lowercased()
                    if !requireTrigger || hasRecognizedTrigger(dialogText)
                        || lowered.contains("password")
                        || (methodSheet && lowered.contains("touch id")) {
                        let target = policy.preference.lazy
                            .compactMap { kind in options.first(where: { $0.kind == kind }) }
                            .first
                        let labels = options.map(\.label)
                        result = .dialog(DetectedSystemDialog(
                            options: options, fields: fields, secureFields: secureFields,
                            target: target,
                            dialogText: dialogText,
                            fullText: dialogText + " " + labels.joined(separator: " "),
                            fingerprint: labels.joined(separator: "|") + "\u{a7}" + dialogText
                        ))
                        return
                    }
                }
            }
            for child in node.children { visit(child) }
        }
        visit(root)
        return result
    }

    /// Buttons are leaves — their wording belongs to the option, not to the
    /// dialog, so `--never-approve` can tell the two apart.
    private static func collect(
        _ node: UINode, buttons: inout [UINode], texts: inout [String], fields: inout [Int],
        secureFields: inout [Int]
    ) {
        // Original browser windows remain scan candidates after native dialog
        // discovery. A toolbar-free popup is still a web document, not a TCC
        // dialog, even when its wording and button count happen to match.
        guard NativeDialogSurface.shouldDescend(role: node.role) else { return }
        if node.role == "AXButton" {
            buttons.append(node)
            return
        }
        let isField = node.role == "AXTextField" || node.role == "AXSecureTextField"
        if isField {
            fields.append(node.id)
            if node.role == "AXSecureTextField" { secureFields.append(node.id) }
        }
        if !node.label.isEmpty { texts.append(node.label) }
        // A field's value is user input, not dialog wording: typing a secret
        // must not change the fingerprint, or the sweep reads the same sheet as
        // a brand-new dialog and presses its grant button again — forever.
        if !node.text.isEmpty, !isField { texts.append(node.text) }
        for child in node.children {
            collect(child, buttons: &buttons, texts: &texts, fields: &fields,
                    secureFields: &secureFields)
        }
    }
}
