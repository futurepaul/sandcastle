#!/usr/bin/env bash
# The release rule, on the operator's machine (docs/nitro-home.md, "The
# release rule"): a new home image is released to only once its own
# attestation, verified here down to AWS's pinned root, names its PCR0,
# which then goes into the home's KMS key policy.
#
#   ./pin-pcr0.sh <a boot's log> <key id> <policy file> [--profile P] [--region R]
#
# The log is the launcher's (`nitro-home up`), whose entrypoint prints
# "home: attestation nonce=<hex> document=<hex>" before it asks KMS for
# anything. The policy file's statement `ReleaseOnlyToTheHomeImage` gets
# that PCR0, the one before kept beside it (a rollback's), and the policy
# is put. nitro-verify (sandcastle-nitro-attest) must be on PATH.
set -euo pipefail
log=$1
key=$2
policy=$3
shift 3
profile=finite
region=us-east-2
while [ $# -gt 0 ]; do
    case "$1" in
        --profile) profile=$2; shift 2 ;;
        --region) region=$2; shift 2 ;;
        *) echo "pin-pcr0: unknown $1" >&2; exit 2 ;;
    esac
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
line=$(grep -o 'attestation nonce=[0-9a-f]* document=[0-9a-f]*' "$log" | tail -n1)
[ -n "$line" ] || { echo "pin-pcr0: no attestation in $log" >&2; exit 1; }
nonce=$(echo "$line" | sed 's/.*nonce=\([0-9a-f]*\).*/\1/')
echo "$line" | sed 's/.*document=\([0-9a-f]*\).*/\1/' | python3 -I -c "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read().strip()))" > "$work/doc"
# checked now, as the verifier checks freshness: pin right after the boot
verified=$(nitro-verify --document "$work/doc" --nonce "$nonce")
echo "$verified" | python3 -I -c "import json, sys; d = json.load(sys.stdin); assert d['verified'] is True" || { echo "pin-pcr0: the document did not verify" >&2; exit 1; }
pcr0=$(echo "$verified" | python3 -I -c "import json, sys; print(json.load(sys.stdin)['pcrs']['0'])")
python3 -I - "$policy" "$pcr0" <<'PY'
import json, sys
path, pcr0 = sys.argv[1:3]
d = json.load(open(path))
(s,) = [s for s in d["Statement"] if s["Sid"] == "ReleaseOnlyToTheHomeImage"]
cond = s["Condition"]["StringEqualsIgnoreCase"]
before = cond["kms:RecipientAttestation:PCR0"]
before = before if isinstance(before, list) else [before]
assert set(pcr0) <= set("0123456789abcdef") and len(pcr0) == 96, "a SHA-384 PCR0"
assert pcr0 != "0" * 96, "debug mode's PCR0 is never released to"
kept = [p for p in before if p != pcr0][-1:]
cond["kms:RecipientAttestation:PCR0"] = [pcr0] + kept
json.dump(d, open(path, "w"), indent=1)
PY
aws --profile "$profile" --region "$region" kms put-key-policy --key-id "$key" --policy-name default --policy "file://$policy"
echo "pin-pcr0: the key now releases to PCR0 ${pcr0:0:16}… (and the one before)"
