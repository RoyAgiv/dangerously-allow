#!/usr/bin/env bash
# Executable-level containment tests for the native-GUI channel.
#
# These do not open an Apple consent dialog and never change TCC. They drive the
# real binary's own decision path: the configuration it resolves from argv, and
# a full capability evaluation against an installed app's live signature. A
# throwaway P-256 issuer is generated per case; nothing here trusts it unless the
# test explicitly passes its fingerprint with --trusted-issuer.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/.build/debug/dangerously-allow"
NODE="$(command -v node)"

[[ -x "$BIN" ]] || { echo "build first: swift build"; exit 1; }
[[ -n "$NODE" ]] || { echo "node is required for the capability fixture"; exit 1; }

pass=0; fail=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  ✓ $name"
        pass=$((pass + 1))
    else
        echo "  ✗ $name"
        echo "      expected: '$expected'"
        echo "      actual:   '$actual'"
        fail=$((fail + 1))
    fi
}

json() { # json <field.path>  (reads JSON on stdin)
    "$NODE" -e '
        let s=""; process.stdin.on("data",d=>s+=d).on("end",()=>{
          let v=JSON.parse(s); for (const k of process.argv[1].split(".")) v = v?.[k];
          console.log(typeof v === "object" ? JSON.stringify(v) : String(v));
        });' "$1"
}

# gen_capability <dir> <nonce> <issued> <expires> <bundle> <team> <req-sha>
#                 <task> <host> <action> <prompt>  -> prints the issuer SPKI SHA-256
gen_capability() {
    "$NODE" - "$@" <<'JS'
const fs = require('fs'), crypto = require('crypto');
const [dir, nonce, issued, expires, bundle, team, requirement, task, host, action, prompt] =
  process.argv.slice(2);
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const payload = {
  Domain: 'dangerously-allow-native-gui-action/v1',
  Purpose: 'native-gui-approve',
  Host: host,
  Task_Id: task,
  Session_Id: '',
  Request_Id: 'req-containment-test',
  App_Bundle_Id: bundle,
  App_Team_Id: team,
  App_Requirement_SHA256: requirement,
  Action: action,
  Prompt_Fingerprint: prompt,
  Nonce: nonce,
  Issued_At: issued,
  Expires_At: expires,
};
const canonical = JSON.stringify(
  Object.fromEntries(Object.keys(payload).sort().map(k => [k, payload[k]]))
);
const signature = crypto.sign('sha256', Buffer.from(canonical), {
  key: privateKey, dsaEncoding: 'der',
}).toString('base64');
fs.writeFileSync(dir + '/capability.json', JSON.stringify({
  Schema: 'dangerously-allow-native-gui-action/v1',
  Algorithm: 'ES256-DER',
  Payload: payload,
  Signature: signature,
  Issuer_Public_Key_Pem: publicKey.export({ type: 'spki', format: 'pem' }),
}, null, 2));
console.log(crypto.createHash('sha256')
  .update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex'));
JS
}

iso() { date -u -r "$1" +"%Y-%m-%dT%H:%M:%SZ"; }
now() { date +%s; }

echo "native GUI containment tests"

STATUS="$("$BIN" --containment-status)"
HOST="$(printf '%s' "$STATUS" | json Host)"
CHATGPT_REQ="$(printf '%s' "$STATUS" | "$NODE" -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).Approved_App_Requirements["com.openai.codex"]))')"

# ---- the bare invocation is observe-only ---------------------------------
check "bare desktop mode is observe-only" "true" "$(printf '%s' "$STATUS" | json Native_Gui_Observe_Only)"
check "bare desktop mode reports no capability" "false" "$(printf '%s' "$STATUS" | json Capability_Configured)"
check "the approved apps are pinned" '["com.openai.codex","com.t3tools.t3code"]' \
    "$(printf '%s' "$STATUS" | json Approved_Apps)"
check "the dialog policy never escalates past once" "once" \
    "$(printf '%s' "$STATUS" | json Required_Policy)"

LOG="$TMP/desktop.log"
"$BIN" --never-approve password >"$LOG" 2>&1 &
pid=$!; sleep 1.5; kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
if grep -q "native dialogs: observe-only" "$LOG"; then
    echo "  ✓ a bare run announces observe-only"; pass=$((pass + 1))
else
    echo "  ✗ a bare run announces observe-only"; sed 's/^/      /' "$LOG"; fail=$((fail + 1))
fi
if grep -q "cards in: none" "$LOG"; then
    echo "  ✓ a bare run presses no app cards"; pass=$((pass + 1))
else
    echo "  ✗ a bare run presses no app cards"; fail=$((fail + 1))
fi
if grep -q 'pressed "' "$LOG"; then
    echo "  ✗ a bare run pressed something"; sed 's/^/      /' "$LOG"; fail=$((fail + 1))
else
    echo "  ✓ a bare run pressed nothing"; pass=$((pass + 1))
fi

# ---- a direct CLI invocation cannot escalate -----------------------------
ALWAYS="$("$BIN" gui --policy always --containment-status)"
check "--policy always is still observe-only" "true" \
    "$(printf '%s' "$ALWAYS" | json Native_Gui_Observe_Only)"
case "$(printf '%s' "$ALWAYS" | json Observe_Only_Reasons)" in
    *policy_not_one_shot*) echo "  ✓ --policy always is refused, not clamped"; pass=$((pass + 1)) ;;
    *) echo "  ✗ --policy always is refused, not clamped"; fail=$((fail + 1)) ;;
esac

# ---- a valid, signed, short-lived capability authorises exactly one press --
mkdir -p "$TMP/good" "$TMP/replay"
GOOD_TRUST="$(gen_capability "$TMP/good" "$(openssl rand -hex 16)" \
    "$(iso "$(now)")" "$(iso "$(( $(now) + 60 ))")" com.openai.codex 2DC432GLL2 "$CHATGPT_REQ" \
    task-containment-test "$HOST" system-dialog-approve containment-diagnostic)"
GOOD_ARGS=(--policy once --never-approve password --task-id task-containment-test
    --host "$HOST" --native-gui-capability "$TMP/good/capability.json"
    --trusted-issuer "$GOOD_TRUST" --replay-store "$TMP/replay")
FIRST="$("$BIN" gui --containment-check "${GOOD_ARGS[@]}")"
check "a valid capability authorises the action" "true" "$(printf '%s' "$FIRST" | json Authorized)"
check "the app signature is verified live" "true" "$(printf '%s' "$FIRST" | json App_Identity_Verified)"
SECOND="$("$BIN" gui --containment-check "${GOOD_ARGS[@]}")"
check "the same capability is a replay the second time" "false" \
    "$(printf '%s' "$SECOND" | json Authorized)"
check "the replay names the one-use ledger" "replayed_capability" \
    "$(printf '%s' "$SECOND" | json Reason)"

# ---- the zero-argument invocation ignores even a capability in the env ----
BARE_LOG="$TMP/bare.log"
DANGEROUSLY_ALLOW_NATIVE_GUI_CAPABILITY="$TMP/good/capability.json" \
DANGEROUSLY_ALLOW_TRUSTED_ISSUERS="$GOOD_TRUST" \
DANGEROUSLY_ALLOW_TASK_ID="task-containment-test" \
    "$BIN" >"$BARE_LOG" 2>&1 &
pid=$!; sleep 1.5; kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
if grep -q "native dialogs: observe-only — never presses" "$BARE_LOG"; then
    echo "  ✓ a bare run ignores a capability in the environment"; pass=$((pass + 1))
else
    echo "  ✗ a bare run ignores a capability in the environment"
    sed 's/^/      /' "$BARE_LOG"; fail=$((fail + 1))
fi

# ---- expiry, lifetime, issuer, task and app scope ------------------------
mkdir -p "$TMP/expired"
EXPIRED_TRUST="$(gen_capability "$TMP/expired" "$(openssl rand -hex 16)" \
    "$(iso "$(( $(now) - 300 ))")" "$(iso "$(( $(now) - 60 ))")" com.openai.codex 2DC432GLL2 "$CHATGPT_REQ" \
    task-x "$HOST" system-dialog-approve containment-diagnostic)"
check "an expired capability is refused" "capability_expired" \
    "$("$BIN" gui --containment-check --policy once --never-approve password \
        --task-id task-x --host "$HOST" --native-gui-capability "$TMP/expired/capability.json" \
        --trusted-issuer "$EXPIRED_TRUST" --replay-store "$TMP/expired/replay" | json Reason)"

mkdir -p "$TMP/long"
LONG_TRUST="$(gen_capability "$TMP/long" "$(openssl rand -hex 16)" \
    "$(iso "$(now)")" "$(iso "$(( $(now) + 300 ))")" com.openai.codex 2DC432GLL2 "$CHATGPT_REQ" \
    task-x "$HOST" system-dialog-approve containment-diagnostic)"
check "a capability living longer than two minutes is refused" "capability_lifetime_too_long" \
    "$("$BIN" gui --containment-check --policy once --never-approve password \
        --task-id task-x --host "$HOST" --native-gui-capability "$TMP/long/capability.json" \
        --trusted-issuer "$LONG_TRUST" --replay-store "$TMP/long/replay" | json Reason)"

mkdir -p "$TMP/other"
OTHER_TRUST="$(gen_capability "$TMP/other" "$(openssl rand -hex 16)" \
    "$(iso "$(now)")" "$(iso "$(( $(now) + 60 ))")" com.openai.codex 2DC432GLL2 "$CHATGPT_REQ" \
    task-x "$HOST" system-dialog-approve containment-diagnostic)"
check "an unlisted issuer is refused" "untrusted_issuer" \
    "$("$BIN" gui --containment-check --policy once --never-approve password \
        --task-id task-x --host "$HOST" --native-gui-capability "$TMP/other/capability.json" \
        --replay-store "$TMP/other/replay" | json Reason)"

mkdir -p "$TMP/task"
TASK_TRUST="$(gen_capability "$TMP/task" "$(openssl rand -hex 16)" \
    "$(iso "$(now)")" "$(iso "$(( $(now) + 60 ))")" com.openai.codex 2DC432GLL2 "$CHATGPT_REQ" \
    task-other "$HOST" system-dialog-approve containment-diagnostic)"
check "a capability bound to another task is refused" "task_mismatch" \
    "$("$BIN" gui --containment-check --policy once --never-approve password \
        --task-id task-x --host "$HOST" --native-gui-capability "$TMP/task/capability.json" \
        --trusted-issuer "$TASK_TRUST" --replay-store "$TMP/task/replay" | json Reason)"

mkdir -p "$TMP/prompt"
PROMPT_TRUST="$(gen_capability "$TMP/prompt" "$(openssl rand -hex 16)" \
    "$(iso "$(now)")" "$(iso "$(( $(now) + 60 ))")" com.openai.codex 2DC432GLL2 "$CHATGPT_REQ" \
    task-x "$HOST" system-dialog-approve some-other-prompt)"
check "a capability bound to another prompt is refused" "prompt_scope_mismatch" \
    "$("$BIN" gui --containment-check --policy once --never-approve password \
        --task-id task-x --host "$HOST" --native-gui-capability "$TMP/prompt/capability.json" \
        --trusted-issuer "$PROMPT_TRUST" --replay-store "$TMP/prompt/replay" | json Reason)"

# ---- an app that is not pinned is rejected ------------------------------
check "an unapproved app is refused" "app_not_approved" \
    "$("$BIN" gui --containment-check --check-app /Applications/Safari.app \
        --policy once --never-approve password --task-id task-x --host "$HOST" \
        --replay-store "$TMP/safari" | json Reason)"
if "$BIN" app Safari >/dev/null 2>&1; then
    echo "  ✗ 'app Safari' must fail"; fail=$((fail + 1))
else
    echo "  ✓ 'app Safari' is rejected"; pass=$((pass + 1))
fi
if "$BIN" app com.anthropic.claudefordesktop >/dev/null 2>&1; then
    echo "  ✗ 'app Claude' must fail closed (not pinned)"; fail=$((fail + 1))
else
    echo "  ✓ 'app Claude' fails closed (not pinned)"; pass=$((pass + 1))
fi

# ---- the two approved apps are still accepted for their cards -----------
for pair in "ChatGPT|com.openai.codex|2DC432GLL2" "T3 Code|com.t3tools.t3code|ARK85ZXQ4Z"; do
    IFS='|' read -r label bundle team <<< "$pair"
    ACCEPT_LOG="$TMP/accept-$bundle.log"
    "$BIN" app "$bundle" --dump >"$ACCEPT_LOG" 2>&1 &
    pid=$!; sleep 1.2; kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    if grep -q "pinned identity: $label $bundle, team $team" "$ACCEPT_LOG"; then
        echo "  ✓ '$label' is accepted and pinned ($bundle)"; pass=$((pass + 1))
    else
        echo "  ✗ '$label' is accepted and pinned ($bundle)"
        sed 's/^/      /' "$ACCEPT_LOG"; fail=$((fail + 1))
    fi
done

# ---- a card presentation is claimed exactly once ------------------------
# A04: two presentations of one approval card produced two physical presses.
# The executable claims a card by host + signed app + window + prompt before it
# presses; a second claim is the distinct duplicate_card_press denial.
echo "card press ledger"
CARD="$TMP/card-ledger"
CARD_ARGS=(app com.openai.codex --card-claim-check --host "$HOST"
    --card-window "ax-id:chatgpt-approval-window" --card-prompt "Allow|Deny§Run the tests"
    --card-store "$CARD")
CARD_FIRST="$("$BIN" "${CARD_ARGS[@]}")"
check "a new card presentation is claimed" "true" "$(printf '%s' "$CARD_FIRST" | json Claimed)"
check "the claim binds the pinned app" "com.openai.codex" \
    "$(printf '%s' "$CARD_FIRST" | json App_Bundle_Id)"
check "the claim binds the pinned team" "2DC432GLL2" \
    "$(printf '%s' "$CARD_FIRST" | json App_Team_Id)"
CARD_SECOND="$("$BIN" "${CARD_ARGS[@]}")"
check "the same card is never claimed twice" "false" \
    "$(printf '%s' "$CARD_SECOND" | json Claimed)"
check "the duplicate has its own denial code" "duplicate_card_press" \
    "$(printf '%s' "$CARD_SECOND" | json Reason)"

# A separate process reading the same store is a replay after a watcher
# restart: the claim is durable, not in-memory.
CARD_RESTART="$("$BIN" "${CARD_ARGS[@]}")"
check "a replay after claim survives a process restart" "duplicate_card_press" \
    "$(printf '%s' "$CARD_RESTART" | json Reason)"

# A genuinely new card is still pressable.
CARD_NEW_PROMPT="$("$BIN" app com.openai.codex --card-claim-check --host "$HOST" \
    --card-window "ax-id:chatgpt-approval-window" --card-prompt "Allow|Deny§Run a different command" \
    --card-store "$CARD")"
check "a genuinely new card is still claimed" "true" \
    "$(printf '%s' "$CARD_NEW_PROMPT" | json Claimed)"
CARD_NEW_WINDOW="$("$BIN" app com.openai.codex --card-claim-check --host "$HOST" \
    --card-window "ax-id:chatgpt-second-window" --card-prompt "Allow|Deny§Run the tests" \
    --card-store "$CARD")"
check "a new window with the same wording is claimed" "true" \
    "$(printf '%s' "$CARD_NEW_WINDOW" | json Claimed)"
CARD_OTHER_APP="$("$BIN" app com.t3tools.t3code --card-claim-check --host "$HOST" \
    --card-window "ax-id:chatgpt-approval-window" --card-prompt "Allow|Deny§Run the tests" \
    --card-store "$CARD")"
check "another pinned app is claimed separately" "true" \
    "$(printf '%s' "$CARD_OTHER_APP" | json Claimed)"
CARD_OTHER_HOST="$("$BIN" app com.openai.codex --card-claim-check --host "some-other-host" \
    --card-window "ax-id:chatgpt-approval-window" --card-prompt "Allow|Deny§Run the tests" \
    --card-store "$CARD")"
check "another host is claimed separately" "true" \
    "$(printf '%s' "$CARD_OTHER_HOST" | json Claimed)"

# An identity with no window cannot be allowed to collapse every card in the
# app onto one entry, so it is refused before the store is touched.
CARD_INCOMPLETE="$("$BIN" app com.openai.codex --card-claim-check --host "$HOST" \
    --card-window "" --card-prompt "Allow|Deny§Run the tests" --card-store "$TMP/card-incomplete")"
check "an unidentifiable card is refused" "incomplete_card_identity" \
    "$(printf '%s' "$CARD_INCOMPLETE" | json Reason)"

# Concurrent claimers: exactly one may win, or two processes would each press.
CONTEND="$TMP/card-contend"
for i in 1 2 3 4 5 6 7 8; do
    "$BIN" app com.openai.codex --card-claim-check --host "$HOST" \
        --card-window "ax-id:contended-window" --card-prompt "Allow|Deny§contended card" \
        --card-store "$CONTEND" >"$TMP/claim-$i.json" 2>/dev/null &
done
wait
winners=0
for f in "$TMP"/claim-*.json; do
    [[ "$(json Claimed <"$f")" == "true" ]] && winners=$((winners + 1))
done
check "concurrent claimers produce exactly one press claim" "1" "$winners"

# ---- a pin must not be confused with the shipped requirement hash -------
case "$CHATGPT_REQ" in
    [0-9a-f][0-9a-f][0-9a-f]*) echo "  ✓ the ChatGPT pin resolves to a SHA-256"; pass=$((pass + 1)) ;;
    *) echo "  ✗ the ChatGPT pin resolves to a SHA-256"; fail=$((fail + 1)) ;;
esac

echo
echo "passed: $pass   failed: $fail"
[[ $fail -eq 0 ]]
