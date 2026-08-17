# AWS IAM User Access Provisioning — Python

Config-driven IAM user provisioning using Python and `boto3`. Users, groups, policies, and console/CLI access are defined in YAML; the script reconciles AWS to match.

---

## What it does

- Creates IAM users (idempotent — skips if already exists)
- Adds users to one or more existing IAM groups
- Attaches inline policies from local JSON files, merged by `Sid` (updates/adds statements without removing untouched ones)
- Enables console access (temp password, reset required on first login)
- Enables CLI access (access key pair)
- Deactivates users: disables access keys and removes console login — **user is not deleted**
- Validates the resulting AWS state after every run

---

## Repository structure

```
.
├── provision_access.py
├── config/
│   └── users.yaml
├── policies/
│   └── *.json
├── generated_credentials/   # gitignored
└── .gitignore
```

---

## Configuration — `config/users.yaml`

```yaml
users:
  - username: <username>
    status: active

    groups:
      - <group name>

    policies:
      - policies/policy_1.json
      - policies/policy_2.json

    console_access: false
    cli_access: true
```

Set `status: inactive` to deactivate a user instead of provisioning them — only `username` and `status` are needed in that case.

---

## Prerequisites

```bash
pip install boto3 pyyaml
aws sts get-caller-identity   # confirm credentials are configured
```

## Run

```bash
python3 provision_access.py
```

Reads `config/users.yaml`, provisions/deactivates each listed user, prints a validation result per user, and writes credentials (if any were generated) to `generated_credentials/<username>.txt`.

---

## Notes

- Credentials are never printed to logs — written once per user to a gitignored local file. Production alternative: AWS Secrets Manager.
- Groups must already exist; the script assigns membership, it doesn't create groups.
- The operator identity running this script should use a dedicated, least-privilege IAM policy scoped to only the actions the script performs.