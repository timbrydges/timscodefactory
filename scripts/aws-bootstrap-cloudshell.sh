#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-plan}"
FACTORY_REGION="${AWS_REGION:-ca-central-1}"
FACTORY_REF="${FACTORY_REF:-main}"
FACTORY_REPOSITORY_URL="https://github.com/timbrydges/timscodefactory.git"
FACTORY_BOOTSTRAP_ROOT="${HOME}/tims-software-factory-bootstrap"
FACTORY_REPOSITORY_DIR="${FACTORY_BOOTSTRAP_ROOT}/repository"
FACTORY_TERRAFORM_DIR="${FACTORY_REPOSITORY_DIR}/infra/aws"
FACTORY_PLAN_PATH="${FACTORY_BOOTSTRAP_ROOT}/factory-bootstrap.tfplan"

case "${MODE}" in
  plan|apply|output) ;;
  *)
    echo "Usage: $0 [plan|apply|output]" >&2
    exit 2
    ;;
esac

if ! command -v aws >/dev/null 2>&1; then
  echo "AWS CLI is required. Run this script inside AWS CloudShell." >&2
  exit 1
fi

FACTORY_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
FACTORY_CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
FACTORY_STATE_BUCKET="tims-software-factory-tfstate-${FACTORY_ACCOUNT_ID}-${FACTORY_REGION}"

echo "AWS account: ${FACTORY_ACCOUNT_ID}"
echo "AWS caller:  ${FACTORY_CALLER_ARN}"
echo "AWS region:  ${FACTORY_REGION}"

if ! command -v terraform >/dev/null 2>&1; then
  sudo dnf install -y dnf-plugins-core
  if ! sudo dnf repolist --all | grep -q '^hashicorp'; then
    sudo dnf config-manager --add-repo \
      https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
  fi
  sudo dnf -y install terraform
fi

terraform version
mkdir -p "${FACTORY_BOOTSTRAP_ROOT}"

if [[ -d "${FACTORY_REPOSITORY_DIR}/.git" ]]; then
  git -C "${FACTORY_REPOSITORY_DIR}" fetch --depth=1 origin "${FACTORY_REF}"
else
  git clone --filter=blob:none --no-checkout \
    "${FACTORY_REPOSITORY_URL}" "${FACTORY_REPOSITORY_DIR}"
  git -C "${FACTORY_REPOSITORY_DIR}" fetch --depth=1 origin "${FACTORY_REF}"
fi
git -C "${FACTORY_REPOSITORY_DIR}" checkout --detach --force FETCH_HEAD

if ! aws s3api head-bucket --bucket "${FACTORY_STATE_BUCKET}" 2>/dev/null; then
  aws s3api create-bucket \
    --bucket "${FACTORY_STATE_BUCKET}" \
    --region "${FACTORY_REGION}" \
    --create-bucket-configuration "LocationConstraint=${FACTORY_REGION}"
fi

aws s3api put-bucket-versioning \
  --bucket "${FACTORY_STATE_BUCKET}" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-encryption \
  --bucket "${FACTORY_STATE_BUCKET}" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-public-access-block \
  --bucket "${FACTORY_STATE_BUCKET}" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-ownership-controls \
  --bucket "${FACTORY_STATE_BUCKET}" \
  --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
aws s3api put-bucket-tagging \
  --bucket "${FACTORY_STATE_BUCKET}" \
  --tagging 'TagSet=[{Key=System,Value=tims-software-factory},{Key=ManagedBy,Value=bootstrap},{Key=Owner,Value=timbrydges}]'

terraform -chdir="${FACTORY_TERRAFORM_DIR}" init -reconfigure \
  -backend-config="bucket=${FACTORY_STATE_BUCKET}" \
  -backend-config="key=timscodefactory/terraform.tfstate" \
  -backend-config="region=${FACTORY_REGION}" \
  -backend-config="encrypt=true" \
  -backend-config="use_lockfile=true"
terraform -chdir="${FACTORY_TERRAFORM_DIR}" validate

FACTORY_OIDC_PROVIDER_ARN=""
while IFS= read -r provider_arn; do
  [[ -z "${provider_arn}" ]] && continue
  provider_url="$(
    aws iam get-open-id-connect-provider \
      --open-id-connect-provider-arn "${provider_arn}" \
      --query Url --output text
  )"
  if [[ "${provider_url}" == "token.actions.githubusercontent.com" ]]; then
    FACTORY_OIDC_PROVIDER_ARN="${provider_arn}"
    break
  fi
done < <(
  aws iam list-open-id-connect-providers \
    --query 'OpenIDConnectProviderList[].Arn' --output text | tr '\t' '\n'
)

FACTORY_TERRAFORM_VARS=(-var="aws_region=${FACTORY_REGION}")
if [[ -n "${FACTORY_OIDC_PROVIDER_ARN}" ]]; then
  echo "Reusing GitHub OIDC provider: ${FACTORY_OIDC_PROVIDER_ARN}"
  FACTORY_TERRAFORM_VARS+=(
    -var="existing_github_oidc_provider_arn=${FACTORY_OIDC_PROVIDER_ARN}"
  )
fi

if [[ "${MODE}" == "output" ]]; then
  terraform -chdir="${FACTORY_TERRAFORM_DIR}" output -json github_repository_variables
  exit 0
fi

terraform -chdir="${FACTORY_TERRAFORM_DIR}" plan \
  -out="${FACTORY_PLAN_PATH}" \
  "${FACTORY_TERRAFORM_VARS[@]}"

if [[ "${MODE}" == "plan" ]]; then
  echo
  echo "Plan saved to ${FACTORY_PLAN_PATH}"
  echo "Review the plan, then run:"
  echo "FACTORY_REF=${FACTORY_REF} bash ${FACTORY_REPOSITORY_DIR}/scripts/aws-bootstrap-cloudshell.sh apply"
  exit 0
fi

terraform -chdir="${FACTORY_TERRAFORM_DIR}" apply "${FACTORY_PLAN_PATH}"
terraform -chdir="${FACTORY_TERRAFORM_DIR}" output -json github_repository_variables \
  | tee "${FACTORY_BOOTSTRAP_ROOT}/github-repository-variables.json"

echo
echo "AWS Factory bootstrap complete."
echo "GitHub variable output saved to: ${FACTORY_BOOTSTRAP_ROOT}/github-repository-variables.json"
