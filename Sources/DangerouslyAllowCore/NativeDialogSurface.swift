/// Native browser dialogs can live inside a large browser window. Search the
/// browser UI, never the web document (including ARIA dialogs authored by it).
public enum NativeDialogSurface {
    public static func isDialog(role: String, subrole: String) -> Bool {
        role == "AXSheet" || role == "AXDialog"
            || subrole == "AXDialog" || subrole == "AXApplicationDialog"
            || subrole == "AXApplicationAlertDialog"
    }

    public static func shouldDescend(role: String) -> Bool {
        role != "AXWebArea"
    }

    /// AppKit reports a secure entry field as `AXTextField` with subrole
    /// `AXSecureTextField`. The subrole is the only thing that tells it apart
    /// from the account-name field directly above it, so normalise it here —
    /// without it every field looks alike and a secret goes to the first one.
    public static func normalizedRole(role: String, subrole: String) -> String {
        role == "AXTextField" && subrole == "AXSecureTextField"
            ? "AXSecureTextField" : role
    }
}
