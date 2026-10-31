# Cloud Security Guardrails & Drift Detection

A hands-on cloud security project that provisions AWS infrastructure as code
and automatically blocks insecure configurations before they are deployed.

## What it does

1. **Terraform** defines an S3 bucket with explicit security controls.
2. **Conftest (OPA/Rego)** checks the Terraform plan against security policies.
3. If a change would weaken security, the policy check **fails** and the change
   can be stopped before it reaches AWS.

## Tech stack

| Tool           | Purpose                |
| -------------- | ---------------------- |
| AWS (S3)       | Cloud infrastructure   |
| Terraform      | Infrastructure as Code |
| Conftest / OPA | Policy as Code         |
| Git / GitHub   | Version control        |

## Security controls

The S3 bucket is configured with:

- **Block Public Access**: all four settings enabled
- **Encryption at rest**: SSE-S3 (AES-256)
- **Versioning**: enabled, to recover deleted or overwritten data
- **Ownership controls**: ACLs disabled (`BucketOwnerEnforced`)

## Project structure

```
cloud-security-guardrails/
├── terraform/
│   └── main.tf      # Infrastructure definition
├── policy/
│   └── s3.rego      # Security policies
└── README.md
```

## How to run

```bash
cd terraform

# Create a plan and convert it to JSON
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check the plan against the policies
conftest test tfplan.json --policy ../policy
```

## Example: catching an insecure change

Changing `block_public_acls` from `true` to `false` produces:

```
FAIL - tfplan.json - main - aws_s3_bucket_public_access_block.security_lab: block_public_acls must be set to true

1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions
```

The policy catches the misconfiguration before it is applied.

## Roadmap

- [x] S3 bucket with explicit security controls
- [x] First policy: S3 public access block
- [ ] Policies for encryption, IAM and network rules
- [ ] Drift detection
- [ ] GitHub Actions pipeline
- [ ] Architecture diagram
