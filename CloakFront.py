#!/usr/bin/env python3
"""
Automate Cobalt Strike C2 redirector setup using AWS CloudFront and Cloudflare DNS

Features
========
* Updates Cloudflare DNS A record for your C2 server’s external IP
* Optionally retrieves a Let’s Encrypt certificate via certbot and creates a JKS keystore
* Builds an AWS CloudFront distribution to front your C2 traffic, with custom AWS tags
* Patches a supplied Malleable C2 profile with the new keystore path (if used), password (if used), and CloudFront hostname

Usage
=====
```bash
sudo python3 c2_setup.py \
  --domain myc2.example.com \
  --cloudflare-token $CF_TOKEN \
  --email yourname@email.com \
  --aws-key $AWS_KEY --aws-secret $AWS_SECRET \
  --consultant j.doe --description "opp-1234" \
  --profile /opt/cobaltstrike/profiles/base.profile [--no-cert]
```
"""
import argparse
import os
import re
import secrets
import shutil
import subprocess
import string
import time
from pathlib import Path

import boto3
import requests

# Constants
GREEN = "\033[32m"
RESET = "\033[0m"
CF_API = "https://api.cloudflare.com/client/v4"
CS_DIR = Path("/opt/cobaltstrike")

# Utility functions
def ok(msg: str):
    print(f"{GREEN}{msg}{RESET}")

def sh(cmd, **kw):
    print(f"$ {' '.join(cmd) if isinstance(cmd,(list,tuple)) else cmd}")
    subprocess.run(cmd, check=True, **kw)

# Ensure dependencies (certbot & keytool)
def ensure_dependencies():
    need = [("certbot", "certbot"), ("keytool", "default-jre-headless")]
    for exe, pkg in need:
        if shutil.which(exe) is None:
            print(f"[!] {exe} missing – installing {pkg}…")
            sh(["apt-get", "update"])
            sh(["apt-get", "install", "-y", pkg])
    ok("[+] Dependencies present")

# Get external IP
def external_ip() -> str:
    return subprocess.check_output(["curl", "-s", "ifconfig.io"]).decode().strip()

# Create/Update Cloudflare A-record
def cloudflare_set_a(domain: str, ip: str, token: str):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    zone = ".".join(domain.split('.')[-2:])
    resp = requests.get(f"{CF_API}/zones", headers=headers, params={"name": zone})
    resp.raise_for_status()
    zones = resp.json().get("result", [])
    if not zones:
        raise RuntimeError(f"Zone '{zone}' not found")
    zone_id = zones[0]["id"]
    recs = requests.get(
        f"{CF_API}/zones/{zone_id}/dns_records", headers=headers,
        params={"name": domain, "type": "A"}
    )
    recs.raise_for_status()
    records = recs.json().get("result", [])
    payload = {"type": "A", "name": domain, "content": ip, "ttl": 120, "proxied": False}
    if records:
        rid = records[0]["id"]
        requests.put(f"{CF_API}/zones/{zone_id}/dns_records/{rid}", headers=headers, json=payload).raise_for_status()
        ok(f"[+] Updated A-record {domain} → {ip}")
    else:
        requests.post(f"{CF_API}/zones/{zone_id}/dns_records", headers=headers, json=payload).raise_for_status()
        ok(f"[+] Created A-record {domain} → {ip}")
    ok(f"Waiting for DNS {domain} to resolve via 4.2.2.2...")
    while True:
      out = subprocess.run(
        ["dig", "@4.2.2.2", "+short", domain],
        stdout=subprocess.PIPE
    ).stdout.decode().split()
      if ip in out:
        ok(f"DNS {domain} now points to {ip}")
        break
      ok(f"Resolved IPs {out}, awaiting {ip}...")
      time.sleep(20)

# Cloudflare DNS record

def cloudflare_set_a(domain: str, ip: str, token: str):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    zone = ".".join(domain.split('.')[-2:])
    resp = requests.get(f"{CF_API}/zones", headers=headers, params={"name": zone})
    resp.raise_for_status()
    zones = resp.json().get("result", [])
    if not zones:
        raise RuntimeError(f"Zone '{zone}' not found")
    zone_id = zones[0]["id"]
    recs = requests.get(
        f"{CF_API}/zones/{zone_id}/dns_records", headers=headers,
        params={"name": domain, "type": "A"}
    )
    recs.raise_for_status()
    records = recs.json().get("result", [])
    payload = {"type": "A", "name": domain, "content": ip, "ttl": 120, "proxied": False}
    if records:
        rid = records[0]["id"]
        requests.put(f"{CF_API}/zones/{zone_id}/dns_records/{rid}", headers=headers, json=payload).raise_for_status()
        ok(f"[+] Updated A-record {domain} → {ip}")
    else:
        requests.post(f"{CF_API}/zones/{zone_id}/dns_records", headers=headers, json=payload).raise_for_status()
        ok(f"[+] Created A-record {domain} → {ip}")
    ok(f"Waiting for DNS {domain} to resolve via 4.2.2.2...")
    while True:
        out = subprocess.run(["dig", "@4.2.2.2", "+short", domain], stdout=subprocess.PIPE).stdout.decode().strip()
        if out:
            ok(f"DNS {domain} → {out.splitlines()[0]}")
            break
        print(f"[!] {domain} not resolvable yet, retrying in 20s...")
        time.sleep(20)

# Certbot + Keystore
def request_certificate(domain: str, email: str):
    print(f"Obtaining certificate for {domain}")
    subprocess.run([
        "certbot","certonly","--non-interactive","--agree-tos",
        "--email",email,
        "--standalone","--preferred-challenges","http",
        "-d",domain
    ], check=True)
    ok(f"[+] Certificate obtained for {domain}")

def bundle_certificate(domain: str, password: str) -> str:
    live = f"/etc/letsencrypt/live/{domain}"
    p12 = f"{domain}.p12"
    jks = f"{domain}.jks"
    print("Bundling PKCS12 archive")
    subprocess.run([
        "openssl","pkcs12","-export",
        "-in",os.path.join(live,"fullchain.pem"),
        "-inkey",os.path.join(live,"privkey.pem"),
        "-out",p12,
        "-name",domain,
        "-passout",f"pass:{password}"
    ], check=True)
    ok(f"[+] Created {p12}")
    print("Importing into Java keystore")
    subprocess.run([
        "keytool","-importkeystore",
        "-deststorepass",password,"-destkeypass",password,
        "-destkeystore",jks,
        "-srckeystore",p12,"-srcstoretype","PKCS12","-srcstorepass",password,
        "-alias",domain
    ], check=True)
    dest = CS_DIR / jks
    subprocess.run(["mv",jks,str(dest)], check=True)
    subprocess.run(["rm","-f",p12], check=True)
    ok(f"[+] Keystore at {dest}")
    return str(dest)

# CloudFront distribution with tags
def create_cloudfront(origin: str, key: str, secret: str, consultant: str, description: str) -> str:
    """Create a CloudFront distribution with tags"""
    cf = boto3.client("cloudfront", aws_access_key_id=key, aws_secret_access_key=secret)
    cfg = {
        "CallerReference": str(time.time()),
        "Origins": {"Quantity": 1, "Items": [{
            "Id": origin,
            "DomainName": origin,
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}
            }
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin,
            "ViewerProtocolPolicy": "allow-all",
            "AllowedMethods": {"Quantity": 7, "Items": ["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"],
                                   "CachedMethods": {"Quantity": 2, "Items": ["GET","HEAD"]}},
            "Compress": False,
            "ForwardedValues": {"QueryString": True, "Cookies": {"Forward": "all"}, "Headers": {"Quantity":1,"Items":["*"]}},
            "MinTTL": 0
        },
        "Comment": "C2 redirector",
        "Enabled": True
    }
    tags = {"Items": [
        {"Key": "Consultant", "Value": consultant},
        {"Key": "Description", "Value": description}
    ]}
    # Use the create_distribution_with_tags API to apply tags at creation
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            'DistributionConfig': cfg,
            'Tags': tags
        }
    )
    domain = resp['Distribution']['DomainName']
    ok(f"[+] CloudFront: {domain}")
    return domain

# Patch profile
def patch_profile(src: Path, dst: Path, keystore: str, passwd: str, cf_host: str, no_cert: bool):
    text = src.read_text()

    # 1) Patch or insert https-certificate block
    if not no_cert:
        cert_block_re = re.compile(r'https-certificate\s*\{.*?\}', flags=re.DOTALL)

        def _ensure_kv(block: str, key: str, value: str) -> str:
            # Replace either 'key "..."' or 'set key "..."'; normalize to 'set key "..."'
            pat = re.compile(rf'(?:set\s+)?{key}\s*"[^"]+"')
            if pat.search(block):
                block = pat.sub(f'set {key} "{value}"', block)
            else:
                block = re.sub(r'\}\s*$', f'    set {key} "{value}"\n}}', block)
            return block

        def _patch_cert_block(block: str) -> str:
            block = _ensure_kv(block, "keystore", keystore)
            block = _ensure_kv(block, "password", passwd)
            return block

        m = cert_block_re.search(text)
        if m:
            patched = _patch_cert_block(m.group(0))
            text = text[:m.start()] + patched + text[m.end():]
        else:
            if not text.endswith('\n'):
                text += '\n'
            text += (
                "https-certificate {\n"
                f'    set keystore "{keystore}"\n'
                f'    set password "{passwd}"\n'
                "}\n"
            )

    # 2) Replace CloudFront hostnames safely

    # Case A: URLs with scheme -> replace only the host part, keep scheme and path intact
    # Example: https://old.cloudfront.net/foo -> https://{cf_host}/foo
    text = re.sub(
        r'(https?://)([\w\.-]+\.cloudfront\.net)',
        lambda m: f'{m.group(1)}{cf_host}',
        text
    )

    # Case B: Bare hostnames (possibly inside quoted or escaped strings)
    # Replace just the hostname token, do not add or remove quotes
    text = re.sub(
        r'(?<![A-Za-z0-9_.-])([\w\.-]+\.cloudfront\.net)(?![A-Za-z0-9_.-])',
        cf_host,
        text
    )

    dst.write_text(text)
    ok(f"[+] Patched profile: {dst}")



# Main entry
def main():
    parser = argparse.ArgumentParser(description="C2 redirector setup")
    parser.add_argument("--domain", required=True, help="C2 server domain")
    parser.add_argument("--cloudflare-token", required=False, help="Cloudflare token (unless --no-cert)")
    parser.add_argument("--email", required=False, help="Email for certbot (unless --no-cert)")
    parser.add_argument("--aws-key", required=True, help="AWS Access Key ID")
    parser.add_argument("--aws-secret", required=True, help="AWS Secret Access Key")
    parser.add_argument("--consultant", required=True, help="Consultant (f.last)")
    parser.add_argument("--description", required=True, help="Opp number and SKU, e.g., 120789-rta")
    parser.add_argument("--profile", required=True, help="Path to C2 profile")
    parser.add_argument("--no-cert", action="store_true", help="Skip cert & keystore steps")
    args = parser.parse_args()
    if not args.no_cert:
        if not (args.cloudflare_token and args.email):
            parser.error("--cloudflare-token and --email are required unless --no-cert is set")

    ensure_dependencies()
    if not args.no_cert:
        ip = external_ip()
        cloudflare_set_a(args.domain, ip, args.cloudflare_token)

    password = ""
    keystore = ""
    if not args.no_cert:
        password = ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(16))
        ok(f"Generated password: {password}")
        request_certificate(args.domain, args.email)
        keystore = bundle_certificate(args.domain, password)

    cf_host = create_cloudfront(args.domain, args.aws_key, args.aws_secret, args.consultant, args.description)
    output = Path(args.profile).with_name(Path(args.profile).name+".modified")
    patch_profile(Path(args.profile), output, keystore, password, cf_host, args.no_cert)
    ok("Setup and profile update complete.")

if __name__ == '__main__':
    main()
