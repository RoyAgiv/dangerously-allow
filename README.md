# dangerously-allow

Auto-approves the permission prompts the **Claude and ChatGPT desktop apps** put
in your way, on macOS.

> **Read this before running it.** This tool can press "Allow" on prompts that
> exist to protect you. A bare invocation is observe-only and presses nothing;
> the click-capable paths are an approved app's own cards (`app <name>`) and a
> containment-gated native dialog with a signed one-use capability. Use it on
> work you can afford to lose, in a directory under version control, and start
> with `--dry-run`.

```bash
dangerously-allow
```

That is the whole thing. No subcommand, no sudo — it observes everything the
desktop agents can ask for, and presses nothing:

| Prompt | Example |
| --- | --- |
| In-app approval card | ChatGPT desktop's "Allow once / Always allow / Deny" |
| Native macOS permission dialog | "ChatGPT wants access to control Finder" |
| Notification banner action | an "Allow" button on a macOS notification |

The desktop apps are the reason this exists. A CLI agent can simply be told to
allow everything — `claude --dangerously-skip-permissions` — and needs no help
from anyone. The desktop apps have no such switch, and they ask constantly:
before touching a file, before driving the browser, and above all before taking
control of your machine, which is a *system* dialog rather than one of their own.

Answering all of that means three unrelated mechanisms, which is why it used to
be three commands you had to remember to start. Forgetting one silently meant a
prompt sat there waiting for a human. Now one process does all three.

## Install

```bash
make install              # builds release, installs into /usr/local/bin
make install PREFIX=~/.local
make uninstall
```

`/usr/local/bin` may need `sudo make install`. tmux is only needed for the
secondary terminal-agent mode (`brew install tmux`).

```bash
make check                # 152 unit tests + 12 tmux end-to-end + 22 containment
make help                 # list targets
```

Grant your terminal Accessibility permission (System Settings → Privacy &
Security → Accessibility). That is the only setup, and it replaces the `sudo`
earlier versions asked for.

## Use

```bash
dangerously-allow                               # observe the desktop, press nothing
dangerously-allow --dry-run --verbose           # see what it would press
dangerously-allow app ChatGPT                   # answer ChatGPT's approval cards
dangerously-allow app com.t3tools.t3code        # answer T3's approval cards
dangerously-allow --never-approve 'Full Disk Access'
```

A bare invocation is **observe-only**. It sweeps the desktop and logs what it
sees, but it presses nothing: neither a native permission dialog nor an in-app
card. That is the safe default for a machine that may also be running agents
nobody supervised — a permission-shaped window can belong to any process, and
pressing its "Allow" creates a system grant.

Answering an app's own approval cards is an explicit, narrow request: name an
approved app with `app <name>`. The two pinned identities are ChatGPT
(`com.openai.codex`, team `2DC432GLL2`) and T3 (`com.t3tools.t3code`, team
`ARK85ZXQ4Z`); the running app's code signature is checked against its
designated requirement at press time, so an unsigned bundle that calls itself
"ChatGPT" is not enough. Any other app is rejected with a usage error.

The whole-desktop mode can also answer cards, but only when you opt in:

```bash
dangerously-allow --app ChatGPT --approve-cards
```

That presses cards in ChatGPT's verified windows and still observes every native
dialog. Without `--approve-cards`, `--app` only scopes what is observed.

The three channels can be run one at a time, which is mostly useful with
`--dump` when a prompt is not recognised and you want the AX tree to paste into
an issue:

```bash
dangerously-allow app ChatGPT --dump            # one app's pruned AX tree
dangerously-allow gui --verbose --dry-run       # dialogs it passed over, and why
dangerously-allow gui --containment-status      # what containment resolved
dangerously-allow notifications                 # observe banners only
```

### Terminal agents (secondary)

A CLI agent can usually just be told to allow everything, so this is for the
cases where it cannot be. The watcher reads the TUI menu out of a tmux pane and
drives it with arrow keys:

```bash
dangerously-allow run claude
dangerously-allow run --policy always codex
dangerously-allow watch my-session --dry-run    # attach to a running agent
```

## Native permission dialogs are a permanent grant

The system-dialog channel is the only one whose answer is written to disk by the
system. A TCC dialog's "Allow" is not a one-time yes — it is an entry in the TCC
database that survives a relaunch and a reboot — so it is classified
`.allowAlways` however mildly the button is worded.

This is also why a window is offered to the system-dialog detector *first*, and
its answer is final. "ChatGPT wants access to control Finder" is a window of
ChatGPT, an app whose cards we also answer, and it satisfies the card detector's
grant-and-refusal shape perfectly well — but that detector reads a plain "Allow"
as `.allowOnce`. Routed there, the cautious card policy would press a permanent
system grant believing it was a one-shot. `DesktopRouter` exists to make that
ordering explicit, and `DesktopRouterTests` pins it.

So the system-dialog channel **defaults to `--policy once`** and, even then, does
not press without a valid containment capability (see CONTAINMENT below). A
plain "Allow" is a `.allowAlways` grant, so it is never eligible: the gate is
pinned to the one-shot tier, and an explicit "Allow Once" is the only button a
capability can authorise. What always holds is that **a refusal or a neutral
button is never pressed, under any policy** — the target is drawn only from
`AllowPolicy.preference`, which lists grant kinds alone:

| Button | Kind | `--policy once` (default) | `--policy always` |
| --- | --- | --- | --- |
| "Allow", "OK" | `allowAlways` | never (and the gate still requires a capability) | never pressed by this executable: a permanent grant |
| "Allow While Using App" | `allowAlways` | never — a permanent entry with a usage condition, not a bounded grant | never |
| "Allow Once" (Location) | `allowOnce` | eligible, but only with a valid one-use capability | eligible with a capability |
| "Open System Settings", "Learn More" | `neutral` | never | never |
| "Don't Allow", "Cancel" | `deny` | never | never |

`--policy always` does not widen the native channel. The executable treats the
native-GUI tier as `once` regardless of what was asked, reports
`policy_not_one_shot` in `--containment-status`, and observes. That is the
direct-CLI bypass this change closes: `dangerously-allow gui --policy always`
cannot become click-capable through flags alone.

The other difference from the `app` path: a system dialog need not offer a
refusal. macOS 15's screen-capture prompt offers "Allow" and "Open System
Settings" and nothing else — the way out is Esc — so the grant-and-refusal
invariant cannot apply here. What stands in for it is the shape (at most five
buttons), a button that grants something, and the containment gates. Recognised wording is *not*
required by default: a keyword list only knows the prompts someone has already
transcribed, and every sentence it has not met — Chrome's remote-debugging
dialog, the next OS release's rephrasing — was being walked past in silence.
`--require-trigger` puts the wording gate back.

If a dialog is not recognised, `--verbose` prints every dialog-shaped window it
passed over, the reason, and each button's classified kind; `--dump` prints
every window carrying text, once, then exits. Paste that into an issue —
wording is the thing that goes stale. macOS 15's screen-capture prompt says
neither "would like to access" nor "Screen Recording", which is exactly how it
slipped past an earlier keyword list.

## Containment

The native-GUI channel is contained at the executable entrypoint. Every
`gui`/whole-desktop scan, the `app` card channel and `notifications` construct a
containment gate from the actual argv and environment, and the only press path
for a native dialog or banner asks that gate first. A `nil` gate — which is what
a missing flag, an unreadable capability, or a future refactor would produce —
is treated as "no capability", so it can only observe.

A native press needs **all five**:

1. **Recognised wording.** The prompt must match a shipped permission sentence
   (`SystemDialogDetector.hasRecognizedTrigger`). An unrecognised
   permission-shaped window is observed, not answered.
2. **A nonempty operator policy.** At least one `--never-approve` pattern must
   be given. A baseline of credential/security phrases (`password`, `keychain`,
   `FileVault`, `System Settings`, `Full Disk Access`, `sudo`, …) is always
   applied on top, and is never a substitute for the operator's own list.
3. **One-shot authorization.** The policy must be `once`; anything broader is
   refused, never clamped.
4. **A pinned app identity.** The window must belong to a running app whose live
   code signature satisfies its designated requirement, and the capability must
   name that same bundle id, team id and requirement SHA-256. Pinned:
   ChatGPT `com.openai.codex` / `2DC432GLL2` and T3 `com.t3tools.t3code` /
   `ARK85ZXQ4Z`. Everything else is `app_not_approved`.
5. **A short-lived, single-use capability** signed by a trusted issuer, bound to
   this host, task, channel, prompt fingerprint and app.

The capability is a JSON envelope. The payload is canonical JSON (sorted keys,
string values, no whitespace) and the signature is ES256-DER over those bytes,
the same shape macs-connect already uses for owner grants:

```json
{
  "Schema": "dangerously-allow-native-gui-action/v1",
  "Algorithm": "ES256-DER",
  "Payload": {
    "Domain": "dangerously-allow-native-gui-action/v1",
    "Purpose": "native-gui-approve",
    "Host": "hyde-m6-2.local",
    "Task_Id": "…", "Session_Id": "…", "Request_Id": "…",
    "App_Bundle_Id": "com.openai.codex",
    "App_Team_Id": "2DC432GLL2",
    "App_Requirement_SHA256": "…",
    "Action": "system-dialog-approve",
    "Prompt_Fingerprint": "…",
    "Nonce": "…", "Issued_At": "…", "Expires_At": "…"
  },
  "Signature": "base64 DER",
  "Issuer_Public_Key_Pem": "-----BEGIN PUBLIC KEY-----…"
}
```

The issuer's fingerprint is the SHA-256 of its SubjectPublicKeyInfo DER
(`openssl pkey -pubin -outform DER`). It is trusted only if it appears in
`--trusted-issuer` (or `DANGEROUSLY_ALLOW_TRUSTED_ISSUERS`). With no trust
entry — the default — no capability can pass. A capability may live at most 120
seconds, is checked against the clock with five seconds of skew, and its nonce
is consumed exactly once through an `O_CREAT|O_EXCL` ledger under
`~/Library/Application Support/dangerously-allow/native-gui-replay` (override
with `--replay-store`). A denial never consumes the nonce; only a fully
authorised press does.

`Task_Id` and `Session_Id` are **correlators, not credentials**. They are
compared to narrow what a signature may authorise, and a capability with the
right task but no valid signature authorises nothing. No task id, session id,
environment variable or CLI flag makes the channel click-capable on its own.

### There is no issuer yet

macs-connect has no authenticated path that mints an application-action
capability. Its request receipts (including PR #1595) are integrity-hashed
*provenance evidence*, not signed authorisations, and its closest signed
contract — `Check_Runtime_Upgrade_Grant`'s ES256-DER owner grant — is bound to a
runtime-upgrade plan and issued offline by the owner. So click-capable native
GUI stays fail-closed: in this build `--policy always` observes, and a valid
capability can only be produced by an out-of-band issuer the operator trusts
explicitly.

What a real issuer must provide, before this channel can press anything:

* an owner-authenticated gateway operation (a tool, not a new daemon) that
  accepts a task-bound request and returns this envelope;
* the payload above with a ≤120 s lifetime and a fresh 32-byte nonce;
* signature by an enrolled key whose SPKI SHA-256 is published to the executing
  host's trust set;
* a durable one-use nonce record shared with the executor (or a ledger the
  executor can atomically claim);
* the pinned app identity and the exact prompt fingerprint the supervisor
  observed.

Until that exists, the honest claim is containment, not approval: this
executable never presses a native permission dialog.

`--containment-status` prints the resolved configuration and the reasons it is
observe-only. `--containment-check` runs one full evaluation against an
installed app's live signature and prints the decision; it consumes the nonce on
success and presses nothing. `tools/containment-test.sh` mints throwaway test
keys and drives both, without opening a consent dialog or touching TCC.

## Owner consent: unattended fleet approval

The capability path above is per-press and needs an issuer, so it cannot answer
a prompt that appears while nobody is present. An owner who accepts that
trade-off can instead authorise the channel with a file:

```json
{
  "Schema": "hyde-owner-consent/v1",
  "Enabled": true,
  "Allow_Permanent": true,
  "Allow_Authentication": true,
  "Allow_Any_Dialog": true,
  "Allow_Destructive": false,
  "Secret_Command": ["/opt/homebrew/bin/node", "/Users/you/.local/bin/Agent_Secrets.mjs",
    "exec", "--keys", "MACOS_LOGIN", "--", "/bin/cat"]
}
```

```bash
chmod 600 ~/.config/hyde/owner-consent.json
dangerously-allow gui --policy always \
  --owner-consent ~/.config/hyde/owner-consent.json \
  --never-approve '(?i)(sudo|password|keychain|touch[ -]?id|filevault)' \
  --poll 1000 --notify
```

The file must be owned by the executing user and must not be group- or
world-writable. A command-line flag alone never enables the mode: without a
valid file the channel behaves exactly as documented above. `Allow_Permanent`
is required for a plain TCC `Allow` (a permanent grant); without it only
bounded one-shot buttons are eligible.

With `Allow_Authentication: true` this path also answers password, Keychain,
Touch ID-sheet, FileVault, Apple Account, sudo and administrator-authentication
prompts, and `Allow_Any_Dialog: true` accepts any dialog-shaped window. A dialog
with a text field is filled from `Secret_Command` before the grant button is
pressed; the value is never logged. macOS secure-event input may still reject
synthetic text in the most protected SecurityAgent fields, and Touch ID itself
cannot be automated.

This path still refuses, structurally:

- every denial or neutral button (`Don't Allow`, `Cancel`, `Open System
  Settings`) — they appear in no policy preference list;
- irreversible destructive confirmations (`Erase All Content and Settings`,
  delete/format/factory reset/reboot) unless `Allow_Destructive` is true;
- any window with no granting button at all.

Every decision is appended to
`~/.local/state/hyde-approval-watchers/consent-audit.jsonl` with a prompt
fingerprint digest, the pressed label and whether a system permission changed.
No prompt body is stored.

The macOS Accessibility grant is still a real owner action. Once granted to the
executing process (or to the LaunchAgent's `node` responsible process),
`AXIsProcessTrusted() = true` is printed at startup and the supervisor heartbeat
records `Accessibility: available`.

## Approval cards, and notification banners

The ChatGPT desktop app (`com.openai.codex`) and T3 (`com.t3tools.t3code`) ask
for approval with a card — "Allow once", "Always allow", "Deny" — not a TUI
menu, so the tmux channel cannot see it. But unlike a terminal drawing, the card
is real UI, and it is fully visible to the Accessibility API. `app <name>` is
the only click-capable card mode, and it only accepts those two pinned
identities; other apps are rejected. To watch just one:

```bash
dangerously-allow app ChatGPT                     # session policy: presses "Allow once"
dangerously-allow app ChatGPT --policy always     # presses "Always allow"
dangerously-allow app ChatGPT --dry-run --verbose # log the card, press nothing
```

An approval card is recognised the same way a TUI menu is: a *small* subtree
holding at least one option that grants and at least one that refuses. A lone
"Allow" button, a toolbar, or a sidebar never qualifies, and the card must
carry request-like wording ("Review command", "File access", "Network
access"…) only if you pass `--require-trigger`. The card's labels were taken
from the app bundle's own string table (`approvalRequestCard.*` in app.asar),
not guessed. `--never-approve` vetoes on the card's text — including the
command it shows.

Notification banners are the same idea with a twist: Notification Center
exposes a banner's buttons as AX *actions on the banner element*, not as child
buttons. `notifications` watches for banners that offer an Allow-style action,
but it is observe-only: the poster cannot be attested from the banner, so the
containment gate declines to press even with a capability.

```bash
dangerously-allow notifications --dry-run     # see what it would press
dangerously-allow notifications               # observe only
```

A banner with no grant action — your average "meeting in 5 minutes" — offers
nothing to press and is never touched. Both need the terminal to have
Accessibility permission (System Settings → Privacy & Security →
Accessibility); neither needs sudo. If a card's wording is not recognised, run
with `--dump` to print the pruned AX tree and paste it into an issue.

## Sweeping without stalling

A system dialog can be posted by any process, so every pass walks every window
of every running app — around 115 apps on an ordinary desktop. Accessibility
calls are synchronous IPC into the target app, and that is the trap: one app
that has stopped answering costs the full messaging timeout *per attribute
read*, and a walk that should take milliseconds takes minutes. An early build of
this mode never completed a single sweep; Finder alone was unbounded.

Three things keep it honest, and the third is the one that matters:

- the messaging timeout is capped globally, so no single read can hang;
- windows outside the card apps get a small node budget, because a permission
  dialog is a title, a sentence and a few buttons — anything larger is an
  ordinary window and walking the rest of it buys nothing;
- **every walk carries a wall-clock deadline.** A node budget bounds a *big*
  tree but not a *slow* one; time is the only unit that bounds both. A window
  that outruns its deadline is abandoned for this pass.

A sweep now costs a few seconds — mostly Finder — at no measurable CPU, since
it is blocked on IPC rather than computing. Run `--verbose` to see the per-pass
timing and which apps are slow.

## Policies

`--policy` decides which grant is acceptable. **A policy never escalates**: it
falls back only to *less* persistent grants, never more. `--policy session` will
not click "Allow for all future sessions" merely because no session option
existed.

| Policy | Clicks | Falls back to |
| --- | --- | --- |
| `once` *(default for native dialogs)* | "Yes", "Allow once" | — |
| `session` *(default for cards)* | "Allow for this session" | a one-time allow |
| `always` | "Allow for all future sessions", "don't ask again", "Trust folder" | session, then once |

Folder trust ("Do you trust the files in this folder?") is classified as a
**permanent** grant even though its label says neither "always" nor "session" —
accepting it lets that directory's config execute code in every future session.
So the default policy deliberately leaves it for a human.

## Why arrow keys and not the option number

Typing the digit looks simpler, and it is wrong. Gemini CLI's `useSelectionList`
fires `SELECT_CURRENT` the instant a digit cannot prefix a longer valid number —
so for a 5-item menu, pressing `2` *already confirms*. A follow-up `Enter` would
then leak into whatever the agent displayed next, potentially confirming a second
prompt nobody looked at.

So the watcher never types digits. It reads the cursor glyph, sends **one** arrow
key, re-captures, and re-reads the cursor — closing the loop on every step. That
also survives menus that skip disabled rows or wrap around the ends, which a
blind "press Down N times" would silently desynchronise from.

## Not firing on the wrong thing

An agent printing a numbered list is not a permission prompt. Before touching a
menu, the watcher requires all of:

1. a contiguous block `1. … N.` (wrapped labels are rejoined),
2. at least one option that grants access **and** at least one that refuses —
   every real permission prompt offers a way out,
3. a question line above the block (`--no-require-trigger` to relax),
4. a visible cursor glyph. If it cannot see which row is highlighted it refuses
   to guess, logs the menu, and leaves the prompt alone.

`--never-approve <regex>` (repeatable) is a hard veto: if the pane matches, the
prompt is left for a human no matter what the policy says.

```bash
dangerously-allow watch agent --never-approve 'rm -rf' --never-approve 'push --force'
```

## When the rules don't recognise a menu

Agents reword their prompts between versions, and a menu the rule classifier has
never seen would otherwise be left untouched. `--llm-fallback` (opt-in; needs
`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`) sends *only* those unrecognised
menus to a model — `claude-haiku-4-5` by default — and asks it to **label** each
row. It never chooses one.

The model reports whether the screen is a permission request and what each row
grants. Those labels are reconciled with the rule engine's own,
**most-reluctant-wins**, and the policy then selects the target exactly as on the
rule path. So a model can never pick a refusal, and can never call a permanent
grant "session-scoped" to slip it past the policy — a disagreement can only make
the watcher *refuse*, never grant more. `--never-approve` is checked before the
pane is sent anywhere, and anything uncertain — the model unsure, the model and
rules disagreeing, no refusal row present, the API unreachable — is left for a
human (with a macOS notification under `--notify`).

```bash
dangerously-allow watch my-session --llm-fallback
dangerously-allow run --llm-fallback --dry-run claude    # log the plan, press nothing
```

## What it will not do

Worth checking for yourself before you trust a tool that clicks "Allow" — every
claim here is one grep away in `Sources/DangerouslyAllowCore/`:

- It never selects a refusal or a neutral option. The target is drawn only from
  `AllowPolicy.preference`, which contains grant kinds and nothing else — on
  the tmux path and the AX path alike.
- It never types an option's digit, so it cannot confirm a menu by accident.
- If it cannot see which row is highlighted, it refuses to act and says so.
- Under the default `session` policy it grants nothing that outlives the agent
  process — no "don't ask again", no "all future sessions", no folder trust.
  In the ChatGPT app, `session` presses "Allow once", because the card offers
  no session-scoped button.
- In `run`/`watch` it reads and writes exactly one tmux pane: the one you name.
- In `app` it reads the AX tree of the one pinned app you name, verifies that
  app's signature, and presses at most one option on a card that offers both a
  grant and a refusal. No other app is accepted.
- A bare invocation presses nothing at all: no native dialog, no card, no
  banner. Card presses require `--app <pinned> --approve-cards`; native presses
  require a signed, single-use capability plus every gate in CONTAINMENT.
- No telemetry and no config file. It makes **no network call unless you pass
  `--llm-fallback`** — which sends unrecognised menus to the Anthropic API, and
  nothing else. The files it writes are the watcher log (`--log <file>`) and,
  only after an authorised native press, the one-use nonce ledger.

`gui` scans the Accessibility tree of every running app to find TCC dialogs,
since the system picks which process presents one. It observes by default. A
press needs recognised wording, an operator `--never-approve` pattern, the
one-shot tier, a pinned app whose live signature satisfies its designated
requirement, and a trusted single-use capability. `--policy always` is reported
as `policy_not_one_shot` and is never a way around the gate.

## A safer alternative first

If you want to auto-approve *everything*, the agent's own flag is safer than
screen-scraping, because it cannot mis-click:

- Claude Code — `--dangerously-skip-permissions`
- Gemini CLI — `--approval-mode=yolo`
- Codex — `--full-auto`

This tool exists for the cases those flags do not cover: approving *selectively*,
attaching to an agent that is **already running**, and working uniformly across
harnesses that expose no such flag.

## Layout

```
Sources/DangerouslyAllowCore/    pure logic, no I/O — where the tests live
  OptionKind.swift               grant kinds; policy preference chains
  OptionClassifier.swift         label -> grant kind
  ScreenParser.swift             ANSI, box borders, wrapped labels, cursor glyph
  PromptDetector.swift           menu detection, target choice, navigation step
  MenuScan.swift                 screen -> rows + rule kinds + navigation state
  Adjudicator.swift              LLM-fallback types; reconcile / validate / merge
  AdjudicatorAPI.swift           Messages API request + response (no network)
  AdjudicatedDetector.swift      scan -> judge -> reconcile -> policy -> outcome
  JSONValue.swift                typed JSON tree for building the request body
  ButtonPrompt.swift             approval cards in a UI element tree
  SystemDialog.swift             native macOS permission dialogs
  DesktopRouter.swift            which detector owns a window; the watched apps
  NativeGuiContainment.swift     pinned identities, capability gate, one-use ledger
Sources/DangerouslyAllow/
  AXTree.swift                   the only file that touches AXUIElement
  DesktopWatcher.swift           the default mode: all three channels, one loop
  AppWatcher.swift               `app` / `notifications`: one app's cards
  AXScanner.swift                `gui`: every app's AX tree -> SystemDialog
  NativeGuiGate.swift            code-signature probe, capability loading, ledger
  ContainmentOptions.swift       containment flags, status and check output
  TmuxChannel.swift              capture-pane / send-keys
  Watcher.swift                  closed-loop poll -> navigate -> confirm
  Runner.swift                   `run`: start the agent in tmux, spawn the watcher
  NetworkAdjudicator.swift       the LLM fallback's one network call (URLSession)
  Notify.swift                   `--notify` macOS notifications
tools/mock-prompt.js             a fake agent menu that renders like the real ones
tools/integration-test.sh        drives it through real tmux
tools/containment-test.sh        executable-level native GUI containment tests
```

Labels and rendering were taken from the shipped harnesses, not guessed —
Gemini CLI's `ToolConfirmationMessage.js` / `BaseSelectionList.js`, and the
string table of the Claude Code binary. `RealCaptureTests.swift` pins verbatim
`capture-pane` output as a fixture.

## Contributing

Prompt wording changes as agents ship new versions. If `dangerously-allow`
mis-reads a menu, run `dangerously-allow watch <session> --verbose --dry-run`,
and paste the parsed menu into an issue along with the raw
`tmux capture-pane -p -t <session>` output. New harnesses are usually just a few
labels in `OptionClassifier` plus a fixture in `RealCaptureTests`.

`make check` must stay green: 120 unit tests, and 12 end-to-end tests that drive a
mock TUI through a real tmux pane.

## License

MIT — see [LICENSE](LICENSE).
