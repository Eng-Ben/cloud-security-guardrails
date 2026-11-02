#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Drift detection
#
# Compares the Terraform configuration with the real AWS infrastructure.
# Exit codes:
#   0 = no drift
#   1 = error
#   2 = drift detected
# -----------------------------------------------------------------------------

set -u

# Always run from the terraform folder, no matter where the script is started
cd "$(dirname "$0")/../terraform" || exit 1

echo "Checking for drift..."

# -detailed-exitcode makes Terraform return 2 when differences are found
terraform plan -detailed-exitcode -input=false -no-color > drift-report.txt 2>&1
exit_code=$?

case $exit_code in
  0)
    echo "✅ No drift detected. AWS matches the Terraform configuration."
    ;;
  2)
    echo "⚠️  DRIFT DETECTED. AWS does not match the Terraform configuration:"
    echo
    grep -E '#.*will be|^ *[~+-] |Plan:' drift-report.txt
    echo
    echo "Full report: terraform/drift-report.txt"
    ;;
  *)
    echo "❌ Error while checking for drift:"
    cat drift-report.txt
    ;;
esac

exit $exit_code