# Cloud Security Guardrails & Drift Detection

[![Policy checks](https://github.com/Eng-Ben/cloud-security-guardrails/actions/workflows/policy-checks.yml/badge.svg)](https://github.com/Eng-Ben/cloud-security-guardrails/actions/workflows/policy-checks.yml)

A hands-on cloud security project that provisions AWS infrastructure as code
and automatically blocks insecure configurations before they are deployed.

## What it does

1. **Terraform** defines an S3 bucket with explicit security controls.
2. **Conftest (OPA/Rego)** checks the Terraform plan against security policies.
3. If a change would weaken security, the policy check **fails** and the change
   can be stopped before it reaches AWS.

## Architecture

```mermaid
flowchart TB
    dev[Developer]

    subgraph Repo["Repository"]
        tf[Terraform code<br/>main.tf]
        rego[Rego policies<br/>policy/]
    end

    subgraph CI["GitHub Actions - on every push"]
        fmt[terraform fmt + validate]
        verify[conftest verify<br/>23 unit tests]
    end

    subgraph Deploy["Before deploy"]
        plan[terraform plan] --> json[tfplan.json] --> check{conftest test}
    end

    dev --> tf
    dev --> rego
    tf --> fmt
    rego --> verify
    tf --> plan
    rego --> check
    check -->|pass| apply[terraform apply]
    check -->|fail| block[Change blocked]
    apply --> aws[(AWS S3 bucket<br/>eu-north-1)]

    subgraph Drift["After deploy"]
        manual[Manual change<br/>in AWS console]
        drift[detect_drift.sh]
    end

    manual -.->|drift| aws
    drift -->|compares with code| aws
```

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

## Policies

| Policy               | Checks                                                           | Result |
| -------------------- | ---------------------------------------------------------------- | ------ |
| `s3.rego`            | All four S3 public access block settings are enabled             | deny   |
| `s3_encryption.rego` | S3 encryption uses an approved algorithm                         | deny   |
| `s3_versioning.rego` | S3 versioning is enabled                                         | deny   |
| `iam.rego`           | IAM policies do not allow all actions (`*`)                      | deny   |
| `iam.rego`           | IAM policies do not allow all actions in a service (e.g. `s3:*`) | warn   |
| `network.rego`       | SSH (22) and RDP (3389) are not open to the internet             | deny   |
| `network.rego`       | Security groups do not allow all traffic from the internet       | deny   |
| `network.rego`       | Other non-web ports open to the internet                         | warn   |

All policies are covered by unit tests (`*_test.rego`), run with `conftest verify --policy policy`.

## Project structure

```
cloud-security-guardrails/
├── .github/workflows/
│   └── policy-checks.yml      # CI pipeline
├── terraform/
│   └── main.tf                # Infrastructure definition
├── policy/
│   ├── iam.rego               # IAM must follow least privilege
│   ├── iam_test.rego          # Unit tests for the IAM policy
│   ├── network.rego           # Admin ports must not be open to the internet
│   ├── network_test.rego      # Unit tests for the network policy
│   ├── s3.rego                # Public access must be blocked
│   ├── s3_encryption.rego     # Encryption must use an approved algorithm
│   ├── s3_versioning.rego     # Versioning must be enabled
│   └── s3_test.rego           # Unit tests for the S3 policies
├── scripts/
│   └── detect_drift.sh        # Drift detection
└── README.md
```

## How to run

bash
cd terraform

# Create a plan and convert it to JSON

terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Check the plan against the policies

conftest test tfplan.json --policy ../policy

## Example: catching an insecure change

Changing `block_public_acls` from `true` to `false` produces:

FAIL - tfplan.json - main - aws_s3_bucket_public_access_block.security_lab: block_public_acls must be set to true

1 test, 0 passed, 0 warnings, 1 failure, 0 exceptions

The policy catches the misconfiguration before it is applied.

## Drift detection

Conftest only checks the **code**. If someone changes a resource directly in
AWS (for example in the console), the code still looks secure. This is called
**drift**.

`scripts/detect_drift.sh` compares the real AWS infrastructure with the
Terraform configuration using `terraform plan -detailed-exitcode`:

| Exit code | Meaning        |
| --------- | -------------- |
| `0`       | No drift       |
| `1`       | Error          |
| `2`       | Drift detected |

Example: versioning was suspended manually outside Terraform:

⚠️ DRIFT DETECTED. AWS does not match the Terraform configuration:

# aws_s3_bucket_versioning.security_lab will be updated in-place

          ~ status     = "Suspended" -> "Enabled"

Plan: 0 to add, 1 to change, 0 to destroy.

Running `terraform apply` restores the secure configuration.

## Roadmap

- [x] S3 bucket with explicit security controls
- [x] Policy: S3 public access block
- [x] Policy: S3 encryption
- [x] Policy: S3 versioning
- [x] Unit tests for all policies
- [x] GitHub Actions pipeline
- [x] Drift detection
- [x] Policy: IAM least privilege
- [x] Policy: network rules
- [x] Architecture diagram
