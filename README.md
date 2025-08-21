# CloakFront
# Cobalt Strike CloudFront C2 Setup Tool

This utility automates the deployment of Cobalt Strike red team infrastructure by:

- **Updating** a Cloudflare DNS A record to point at your C2 server’s external IP
- **Optionally** obtaining a Let’s Encrypt TLS certificate via **certbot** and packaging it into a Java keystore (JKS)
- **Creating** an AWS CloudFront distribution to front your C2 traffic
- **Patching** a Malleable C2 profile to reference the newly generated keystore (and password) along with the CloudFront hostname

<img width="720" height="393" alt="image" src="https://github.com/user-attachments/assets/bf74aa8d-9351-495c-8c69-0faac5d433e0" />

source: https://bigb0ss.medium.com/redteam-c2-redirector-cloud-fronting-setup-aws-e7ed561a3a6c



## Prerequisites

- Python 3.7+
- `bash`, `curl`, `dig`
- Access to:
  - Cloudflare API (zone edit privileges)
  - AWS API keys (CloudFront privileges)
- `certbot` and `keytool` (script will install via `apt` if missing)

## Installation

1. Clone or copy the script into your C2 tools directory:
   ```bash
   git clone https://github.com/beartrapt/CloakFront
   cd CloakFront
   ```
2. Ensure Python dependencies are installed:
   ```bash
   pipenv --python 3 shell
   pip install -r requirements.txt
   ```

## Usage

### Full workflow (with certificate)

```bash
sudo python3 ./CloakFront.py \
  --domain  c2.example.com \
  --cloudflare-token $CF_TOKEN \
  --email yourname@email.com \
  --aws-key  $AWS_KEY     \
  --aws-secret $AWS_SECRET\
  --consultant j.doe       \
  --description "opp-1234" \
  --profile /opt/cobaltstrike/profiles/base.profile
```

**What happens:**

1. Installs missing dependencies (`certbot`, `keytool`).
2. Resolves your host’s public IP and updates/creates the Cloudflare A record.
3. Obtains a Let’s Encrypt certificate for `--domain` via **certbot**.
4. Bundles the cert into a PKCS12 archive and then into a Java keystore.
5. Spins up a CloudFront distribution tagged with your consultant name & description.
6. Patches the existing Malleable C2 profile:
   - Inserts the keystore path & password into the `https-certificate` block (or creates the `https-certificate` block if needed
   - Replaces any `*.cloudfront.net` host strings with the new distribution domain
7. Outputs the modified profile at `base.profile.modified`.

### Minimal workflow (skip certificate)

This is useful in a situation where your previous CloudFront distribution got burned and you need a new one, but already have a TLS cert so there's no point in requesting a new one.

```bash
sudo python3 CloakFront.py \
  --domain  c2.example.com \
  --aws-key  $AWS_KEY     \
  --aws-secret $AWS_SECRET\
  --consultant j.doe       \
  --description "opp-1234" \
  --profile /opt/cobaltstrike/profiles/base.profile \
  --no-cert
```

**What happens:**

- Skips steps 2–4 (DNS update, certbot, keystore).
- Immediately creates the CloudFront distribution (with tags).
- Patches only the CloudFront hostname in your Malleable profile.

## Script Arguments

| Flag                 | Required | Description                                                            |
| -------------------- | -------- | ---------------------------------------------------------------------- |
| `--domain`           | Yes      | FQDN of your C2 server                                                 |
| `--cloudflare-token` | Yes¹     | Cloudflare API token (skip if `--no-cert`)                             |
| `--email`            | Yes¹     | Email address for Let’s Encrypt registration (skip if `--no-cert`)     |
| `--aws-key`          | Yes      | AWS Access Key ID                                                      |
| `--aws-secret`       | Yes      | AWS Secret Access Key                                                  |
| `--consultant`       | Yes      | Consultant name in `f.last` format                                     |
| `--description`      | Yes      | Description of the opp (e.g., `opp-1234`)                          |
| `--profile`          | Yes      | Path to your existing Malleable C2 profile                             |
| `--no-cert`          | No       | Skip certbot and keystore creation; only CloudFront & profile patching |

¹ Required only when not using `--no-cert`.
