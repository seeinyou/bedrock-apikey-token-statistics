# Bedrock API Key Token Statistics

A single-file Python CLI tool that generates per-IAM-user, per-model token consumption reports for Amazon Bedrock, with optional USD cost calculation.

## Background

Organizations using Amazon Bedrock with API keys need visibility into how individual users consume tokens across different models. Bedrock's model invocation logging captures detailed request-level data in S3 and/or CloudWatch, but there is no built-in aggregation by IAM user and model.

This tool solves that problem. It:

1. **Auto-detects** your Bedrock model invocation logging configuration (S3, CloudWatch, or both) via the `GetModelInvocationLoggingConfiguration` API.
2. **Queries** log data using one of three engines: Athena (default for S3), S3 direct download, or CloudWatch Logs Insights.
3. **Resolves** IAM identities from ARNs and maps them to Bedrock API key credential IDs via `iam:ListServiceSpecificCredentials`.
4. **Resolves** inference profile ARNs (application profiles, system profiles, and direct model IDs) to human-readable model identifiers.
5. **Merges** results from multiple log sources, with S3/Athena as the primary source and CloudWatch filling in any gaps.
6. **Computes** USD costs per user per model using a 3-tier pricing lookup: in-memory cache, local JSON file cache (24-hour TTL), and the AWS Pricing API, with built-in fallback pricing for common models.

## Purposes

- **Per-IAM-user token consumption tracking** -- break down input, output, cache-read, and cache-write tokens by IAM user.
- **Per-model usage breakdown** -- see which models each user is calling and how much they consume.
- **Optional USD cost calculation** -- automatically look up Bedrock pricing and compute costs per user per model.
- **Multiple query engines** -- choose between Athena (SQL aggregation), S3 direct (concurrent download/parse), or CloudWatch Logs Insights.
- **Multiple output formats** -- stdout table with per-user subtotals and grand total, CSV, plain text, or a self-contained interactive HTML report (sortable, filterable, with summary cards and a pricing reference section).
- **Flexible user filtering** -- default filters to `BedrockAPIKey-*` IAM users; optionally include all IAM users.

## Pre-requisites

### Python

- Python 3.10 or later (the script uses `type1 | type2` union syntax from PEP 604).

### AWS Credentials

- Configured AWS credentials via environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), an AWS profile (`AWS_PROFILE`), or an instance/container role.

### Bedrock Logging

- Amazon Bedrock **model invocation logging** must be enabled in the target region. The tool supports logs stored in S3, CloudWatch, or both. You can also override the auto-detected configuration with CLI arguments.

### IAM Permissions

The script runs a permission verification step before executing the main workflow. The required permissions depend on which features and engines you use.

**Always required:**

| Permission | Purpose |
|---|---|
| `sts:GetCallerIdentity` | Verify caller identity |
| `bedrock:GetModelInvocationLoggingConfiguration` | Auto-detect logging config |
| `bedrock:GetInferenceProfile` | Resolve inference profile ARNs to model IDs |
| `bedrock:ListInferenceProfiles` | Build profile lookup table |
| `bedrock:ListFoundationModels` | Build model lookup table |
| `iam:ListUsers` | Enumerate IAM users |
| `iam:ListServiceSpecificCredentials` | Map IAM users to Bedrock API key credential IDs |

**When using S3 as a log source:**

| Permission | Purpose |
|---|---|
| `s3:GetObject` | Read log files from S3 |
| `s3:ListBucket` | List log file keys |

**When using the Athena query engine (default for S3):**

| Permission | Purpose |
|---|---|
| `athena:StartQueryExecution` | Run aggregation queries |
| `athena:GetQueryExecution` | Poll query status |
| `athena:GetQueryResults` | Retrieve query results |
| `s3:GetBucketLocation` | Determine bucket region for Athena |
| `s3:PutObject` | Write Athena query results to S3 |

**When using CloudWatch as a log source:**

| Permission | Purpose |
|---|---|
| `logs:DescribeLogGroups` | Verify log group exists |
| `logs:StartQuery` | Run Logs Insights queries |
| `logs:GetQueryResults` | Retrieve query results |

**Optional (for `--with-pricing`):**

| Permission | Purpose |
|---|---|
| `pricing:GetProducts` | Look up Bedrock model pricing from the AWS Pricing API |

> If the Pricing API is unavailable, the tool falls back to built-in pricing constants for common Anthropic, Amazon Nova, and DeepSeek models.

## Installation

```bash
# Clone the repository
git clone https://github.com/<your-org>/bedrock-apikey-token-statistics.git
cd bedrock-apikey-token-statistics

# Install dependencies (only boto3)
pip install -r requirements.txt

# Verify AWS credentials are configured
aws sts get-caller-identity
```

## Execution

The script is located at `src/statistics-token-consumption-for-iam-users.py`.

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--region` | `us-east-1` (or `AWS_REGION` env var) | AWS region to query |
| `--start-date` | *(none)* | Start date in `YYYY-MM-DD` format. Mutually exclusive with `--hours`. |
| `--end-date` | Today | End date in `YYYY-MM-DD` format |
| `--hours` | `24` (when no date args given) | Lookback N hours from now. Mutually exclusive with `--start-date`. |
| `--query-engine` | `athena` | Query engine for S3 log source: `athena` or `s3` |
| `--with-pricing` | `off` | Include pricing/cost columns: `true` or `off` |
| `--bedrock-apikey-only` | `yes` | Filter to `BedrockAPIKey-*` IAM users only: `yes` or `no` |
| `--output` | *(none, stdout only)* | Output filename. Extension determines format: `.csv`, `.html`, or `.txt` |
| `--output-dir` | `tests/` (relative to project root) | Directory for output files when `--output` is a bare filename |
| `--s3-bucket` | *(auto-detected)* | Override auto-detected S3 bucket name |
| `--s3-prefix` | *(auto-detected)* | Override auto-detected S3 key prefix |
| `--cw-log-group` | *(auto-detected)* | Override auto-detected CloudWatch log group |
| `--athena-output` | `s3://<bucket>/athena-results/bedrock-token-usage/` | S3 location for Athena query results |
| `--workers` | `30` | Thread count for S3 direct engine |

### Usage Examples

**Date range mode (auto-detects logging configuration):**

```bash
python3 src/statistics-token-consumption-for-iam-users.py \
    --start-date=2026-03-10 --end-date=2026-03-19
```

**Lookback mode (last 24 hours by default):**

```bash
python3 src/statistics-token-consumption-for-iam-users.py --hours=48
```

**With pricing and CSV output:**

```bash
python3 src/statistics-token-consumption-for-iam-users.py \
    --start-date=2026-03-10 --end-date=2026-03-19 \
    --with-pricing=true --output=report.csv
```

**Interactive HTML report with pricing:**

```bash
python3 src/statistics-token-consumption-for-iam-users.py \
    --start-date=2026-03-01 --end-date=2026-03-19 \
    --with-pricing=true --output=report.html
```

**Include all IAM users (not just API key users):**

```bash
python3 src/statistics-token-consumption-for-iam-users.py \
    --start-date=2026-03-10 --bedrock-apikey-only=no
```

**Use S3 direct engine instead of Athena:**

```bash
python3 src/statistics-token-consumption-for-iam-users.py \
    --start-date=2026-03-10 --query-engine=s3
```

**Override auto-detected log sources:**

```bash
python3 src/statistics-token-consumption-for-iam-users.py \
    --start-date=2026-02-01 --end-date=2026-03-19 \
    --region=us-west-2 \
    --with-pricing=true \
    --s3-bucket=my-logging-bucket \
    --s3-prefix=logs/bedrock/ \
    --cw-log-group=/aws/bedrock/api/invokemodel/claude/ \
    --output=report.html
```

### Output Formats

- **Stdout (default):** A formatted table printed to the terminal with per-user subtotals and a grand total row. Always produced regardless of `--output`.
- **CSV (`.csv`):** Machine-readable format with columns for IAM user, API key IDs, application profile, model ID, request count, token counts, and (when `--with-pricing=true`) cost columns.
- **HTML (`.html`):** A self-contained interactive report using React (loaded from CDN). Features sortable columns, a text filter, summary cards, per-user subtotals, a grand total, and a collapsible pricing reference section.
- **Text (`.txt`):** A simple one-line-per-record format suitable for log ingestion.

## Troubleshooting

### Missing IAM Permissions

The script runs an automated permission verification check before executing the main workflow. If any required permission fails, the script prints a `FAIL` line with the specific error and then lists all required IAM permissions for the current run configuration. Resolve the listed permission gaps and retry.

### No Logging Configuration Detected

If the script exits with:
```
Error: Bedrock model invocation logging is not configured.
```
This means no S3 bucket or CloudWatch log group was found via the `GetModelInvocationLoggingConfiguration` API, and no CLI overrides were provided. Either:
- Enable model invocation logging in the **Amazon Bedrock console** (Settings > Model invocation logging).
- Provide explicit overrides: `--s3-bucket` and `--s3-prefix`, or `--cw-log-group`.

### Athena Query Failures

If the Athena engine fails, check that:
- The IAM role has all Athena-related permissions listed above.
- The Athena output location (`--athena-output` or the default `s3://<bucket>/athena-results/`) is writable.
- The Athena engine recreates the database/table (`DROP` + `CREATE`) on every run. If you see schema errors, they are typically transient.

### Empty Results

If the script reports "No token usage data found" or "No IAM users found":
- Verify that model invocation logging has been active during the queried time range.
- If filtering by API key users (the default), try `--bedrock-apikey-only=no` to see if data exists for other IAM identities.
- Confirm the `--region` matches the region where Bedrock calls were made and logging was configured.

### Pricing Fallback Behavior

When `--with-pricing=true` is set:
- The tool first checks an in-memory cache, then a local JSON file (`src/cached/amazon-bedrock-pricing-cache-{region}.json` with a 24-hour TTL), and finally queries the AWS Pricing API.
- If the Pricing API is unreachable or the `pricing:GetProducts` permission is missing, the permission check shows a `WARN` (not `FAIL`) and the tool proceeds using built-in fallback pricing for common models (Anthropic Claude, Amazon Nova, DeepSeek R1).
- Models not found in either the Pricing API or the fallback table will show no cost data.

### S3 Direct Engine Limitations

When using `--query-engine=s3`, the `Request_count` column will be empty (`None`) because the S3 direct engine processes individual log records rather than running SQL aggregation. Use the Athena engine if you need request counts.

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
