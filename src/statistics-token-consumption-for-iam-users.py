#!/usr/bin/env python3
"""
Statistics: Token Consumption for Bedrock IAM Users

Unified script that auto-detects logging configuration (S3, CloudWatch, or both)
and produces a per-IAM-user, per-model token consumption report with optional pricing.

Auto-detects Bedrock model invocation logging configuration and queries both
S3/Athena and CloudWatch Logs Insights sources, merging results with S3 as primary.

Prerequisites:
  1. Enable Bedrock model invocation logging (S3 and/or CloudWatch)
  2. IAM permissions: bedrock:GetModelInvocationLoggingConfiguration,
     s3:GetObject, s3:ListBucket, athena:StartQueryExecution,
     logs:StartQuery, logs:GetQueryResults, iam:ListUsers,
     iam:ListServiceSpecificCredentials, bedrock:GetInferenceProfile,
     bedrock:ListInferenceProfiles, pricing:GetProducts

Usage:
  # Date range with auto-detected logging config:
  python3 statistics-token-consumption-for-iam-users.py --start-date=2026-03-10 --end-date=2026-03-19

  # Lookback mode:
  python3 statistics-token-consumption-for-iam-users.py --hours=24

  # With pricing:
  python3 statistics-token-consumption-for-iam-users.py --start-date=2026-03-10 --end-date=2026-03-19 \\
      --with-pricing=true --output=report.csv

  # Override S3 bucket/prefix:
  python3 statistics-token-consumption-for-iam-users.py --start-date=2026-03-10 \\
      --bucket=my-bucket --prefix=logs/bedrock/

  # Include all IAM users (not just BedrockAPIKey-*):
  python3 statistics-token-consumption-for-iam-users.py --start-date=2026-03-10 --bedrock-apikey-only=no

  # Use S3 direct engine instead of Athena:
  python3 statistics-token-consumption-for-iam-users.py --start-date=2026-03-10 --engine=s3

Example:
    python3 statistics-token-consumption-for-iam-users.py \
        --start-date 2026-03-01 \
        --end-date 2026-03-19 \
        --region us-west-2 \
        --with-pricing true \
        --bedrock-apikey-only yes \
        --cw-log-group /aws/bedrock/api/invokemodel/claude/ \
        --s3-bucket jm-uswest2-dev-1 \
        --s3-prefix logs/bedrock/ \
        --query-engine athena \
        --output report_20260319.html
"""

import argparse
import csv
import gzip
import json
import os
import re
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

import html as html_module
import threading

import boto3
from botocore.exceptions import ClientError


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATHENA_QUERY_TIMEOUT_SEC = 600  # 10 minutes
CW_QUERY_TIMEOUT_SEC = 600     # 10 minutes

ATHENA_DATABASE = "bedrock_logs_db"
ATHENA_TABLE = "bedrock_invocation_logs"
ATHENA_OUTPUT_PREFIX = "athena-results/bedrock-token-usage/"
MAX_WORKERS = 30
LIST_WORKERS = 10

REGION_TO_LOCATION = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-north-1": "EU (Stockholm)",
    "eu-south-1": "EU (Milan)",
    "eu-south-2": "Europe (Spain)",
    "eu-central-2": "Europe (Zurich)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "ap-southeast-4": "Asia Pacific (Melbourne)",
    "ap-southeast-5": "Asia Pacific (Malaysia)",
    "ap-southeast-7": "Asia Pacific (Thailand)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-east-1": "Asia Pacific (Taipei)",
    "ca-central-1": "Canada (Central)",
    "ca-west-1": "Canada West (Calgary)",
    "sa-east-1": "South America (Sao Paulo)",
    "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)",
    "af-south-1": "Africa (Cape Town)",
    "il-central-1": "Israel (Tel Aviv)",
    "mx-central-1": "Mexico (Central)",
    "ap-southeast-6": "Asia Pacific (New Zealand)",
}

# Fallback pricing (USD per 1K tokens) — regex matched against display_model_id
FALLBACK_PRICING = [
    (r"global\.anthropic\.claude-opus-4-6", {
        "input": 0.005, "output": 0.025,
        "cache_read": 0.0005, "cache_write": 0.00625,
    }),
    (r"global\.anthropic\.claude-sonnet-4-6", {
        "input": 0.003, "output": 0.015,
        "cache_read": 0.0003, "cache_write": 0.00375,
    }),
    (r"anthropic\.claude-opus-4-6", {
        "input": 0.0055, "output": 0.0275,
        "cache_read": 0.00055, "cache_write": 0.006875,
    }),
    (r"anthropic\.claude-sonnet-4-6", {
        "input": 0.0033, "output": 0.0165,
        "cache_read": 0.00033, "cache_write": 0.004125,
    }),
    (r"anthropic\.claude-opus-4(?!-[5-9])", {
        "input": 0.015, "output": 0.075,
        "cache_read": 0.0015, "cache_write": 0.01875,
    }),
    (r"anthropic\.claude-sonnet-4-5", {
        "input": 0.003, "output": 0.015,
        "cache_read": 0.0003, "cache_write": 0.00375,
    }),
    (r"anthropic\.claude-sonnet-4(?!-[5-9])", {
        "input": 0.003, "output": 0.015,
        "cache_read": 0.0003, "cache_write": 0.00375,
    }),
    (r"anthropic\.claude-haiku-4-5", {
        "input": 0.0008, "output": 0.004,
        "cache_read": 0.00008, "cache_write": 0.001,
    }),
    (r"anthropic\.claude-3-haiku", {
        "input": 0.00025, "output": 0.00125,
        "cache_read": 0.0, "cache_write": 0.0,
    }),
    (r"amazon\.nova-pro", {
        "input": 0.0008, "output": 0.0032,
        "cache_read": 0.0002, "cache_write": 0.0,
    }),
    (r"amazon\.nova-lite", {
        "input": 0.00006, "output": 0.00024,
        "cache_read": 0.000015, "cache_write": 0.0,
    }),
    (r"amazon\.nova-micro", {
        "input": 0.000035, "output": 0.00014,
        "cache_read": 0.00000875, "cache_write": 0.0,
    }),
    (r"deepseek\.r1", {
        "input": 0.00135, "output": 0.0054,
        "cache_read": 0.0, "cache_write": 0.0,
    }),
]

_PRICING_MODEL_NAME_TO_ID = {
    "Nova Pro": "amazon.nova-pro",
    "Nova Lite": "amazon.nova-lite",
    "Nova Micro": "amazon.nova-micro",
    "Nova 2.0 Pro": "amazon.nova-pro-v2",
    "Nova 2.0 Lite": "amazon.nova-lite-v2",
    "Nova 2.0 Omni": "amazon.nova-omni-v2",
    "Nova Premier": "amazon.nova-premier",
    "R1": "deepseek.r1",
}

_INF_TYPE_MAP = {
    "Input tokens": "input",
    "Output tokens": "output",
    "Prompt cache read input tokens": "cache_read",
    "Prompt cache write input tokens": "cache_write",
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Track Bedrock token consumption per IAM user per model ID.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--region", type=str, default=None,
                        help="AWS region (default: us-east-1)")
    parser.add_argument("--start-date", type=str, default=None,
                        help="Start date YYYY-MM-DD (required unless --hours given)")
    parser.add_argument("--end-date", type=str, default=None,
                        help="End date YYYY-MM-DD (default: today)")
    parser.add_argument("--hours", type=int, default=None,
                        help="Lookback N hours from now (mutually exclusive with date args)")
    parser.add_argument("--query-engine", choices=["s3", "athena"], default="athena",
                        help="Query engine for S3 source (default: athena)")
    parser.add_argument("--with-pricing", type=str, default="off", choices=["true", "off"],
                        help="Include pricing/cost columns (default: off)")
    parser.add_argument("--bedrock-apikey-only", type=str, default="yes", choices=["yes", "no"],
                        help="Filter to BedrockAPIKey-* users (default: yes)")
    default_output_dir = str(Path(__file__).resolve().parent.parent / "tests")
    parser.add_argument("--output", type=str, default=None,
                        help="Output filename (.csv, .txt, or .html)")
    parser.add_argument("--output-dir", type=str, default=default_output_dir,
                        help=f"Directory for output files (default: {default_output_dir})")
    parser.add_argument("--s3-bucket", type=str, default=None,
                        help="Override auto-detected S3 bucket")
    parser.add_argument("--s3-prefix", type=str, default=None,
                        help="Override auto-detected S3 prefix")
    parser.add_argument("--cw-log-group", type=str, default=None,
                        help="Override auto-detected CloudWatch log group")
    parser.add_argument("--athena-output", type=str, default=None,
                        help="S3 location for Athena query results")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS,
                        help=f"Thread count for S3 direct engine (default: {MAX_WORKERS})")
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Time Range
# ---------------------------------------------------------------------------

def resolve_time_range(args) -> tuple[datetime, datetime, str]:
    """Return (start_utc, end_utc, description) from --start-date/--end-date or --hours."""
    if args.start_date and args.hours:
        print("Error: --start-date/--end-date and --hours are mutually exclusive.",
              file=sys.stderr)
        sys.exit(1)

    if args.start_date:
        try:
            start = datetime.strptime(args.start_date, "%Y-%m-%d").replace(
                tzinfo=timezone.utc)
        except ValueError:
            print(f"Error: invalid --start-date format '{args.start_date}'. Use YYYY-MM-DD.",
                  file=sys.stderr)
            sys.exit(1)

        if args.end_date:
            try:
                end = datetime.strptime(args.end_date, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc)
            except ValueError:
                print(f"Error: invalid --end-date format '{args.end_date}'. Use YYYY-MM-DD.",
                      file=sys.stderr)
                sys.exit(1)
        else:
            end = datetime.now(timezone.utc)

        if start >= end:
            print(f"Error: --start-date ({args.start_date}) must be before --end-date.",
                  file=sys.stderr)
            sys.exit(1)

        desc = f"{args.start_date} to {args.end_date or 'now'}"
        return start, end, desc

    hours = args.hours or int(os.environ.get("HOURS", "24"))
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    desc = f"last {hours}h"
    return start, end, desc


# ---------------------------------------------------------------------------
# IAM Permission Verification
# ---------------------------------------------------------------------------

# Permissions grouped by feature. Each entry: (service, api_action, test_callable).
# test_callable receives the boto3 client and returns None on success or an error string.

def _check_sts_identity(region: str) -> tuple[str | None, str]:
    """Verify STS access and return (caller_arn_or_none, error_or_empty)."""
    try:
        sts = boto3.client("sts", region_name=region)
        identity = sts.get_caller_identity()
        arn = identity.get("Arn", "unknown")
        return arn, ""
    except Exception as e:
        return None, str(e)


def verify_permissions(region: str, engine: str, with_pricing: bool,
                       s3_bucket: str | None, log_group: str | None) -> bool:
    """Test required AWS API permissions before running the main workflow.

    Performs lightweight dry-run or minimal API calls for each required
    permission. Prints a table of results and returns True if all critical
    permissions pass.
    """
    print("Verifying AWS IAM permissions...\n")

    caller_arn, sts_err = _check_sts_identity(region)
    if caller_arn:
        print(f"  Caller identity: {caller_arn}")
    else:
        print(f"  Error: unable to determine caller identity: {sts_err}",
              file=sys.stderr)
        print("  Ensure AWS credentials are configured (env vars, profile, "
              "or instance role).", file=sys.stderr)
        return False

    # Build list of (description, service, test_func) — test_func() -> None|error_str
    checks: list[tuple[str, callable]] = []

    # --- Always required ---
    def _check_bedrock_logging():
        try:
            client = boto3.client("bedrock", region_name=region)
            client.get_model_invocation_logging_configuration()
        except ClientError as e:
            return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
        except Exception as e:
            return str(e)
        return None

    def _check_bedrock_list_profiles():
        try:
            client = boto3.client("bedrock", region_name=region)
            client.list_inference_profiles(maxResults=1)
        except ClientError as e:
            return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
        except Exception as e:
            return str(e)
        return None

    def _check_bedrock_list_models():
        try:
            client = boto3.client("bedrock", region_name=region)
            client.list_foundation_models()
        except ClientError as e:
            return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
        except Exception as e:
            return str(e)
        return None

    def _check_iam_list_users():
        try:
            client = boto3.client("iam", region_name=region)
            client.list_users(MaxItems=1)
        except ClientError as e:
            return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
        except Exception as e:
            return str(e)
        return None

    checks.append(("bedrock:GetModelInvocationLoggingConfiguration",
                    _check_bedrock_logging))
    checks.append(("bedrock:ListInferenceProfiles",
                    _check_bedrock_list_profiles))
    checks.append(("bedrock:ListFoundationModels",
                    _check_bedrock_list_models))
    checks.append(("iam:ListUsers", _check_iam_list_users))

    # --- S3 permissions (when S3 source is used) ---
    if s3_bucket:
        def _check_s3_list():
            try:
                client = boto3.client("s3", region_name=region)
                client.list_objects_v2(Bucket=s3_bucket, MaxKeys=1)
            except ClientError as e:
                return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
            except Exception as e:
                return str(e)
            return None

        checks.append((f"s3:ListBucket (bucket: {s3_bucket})", _check_s3_list))

        if engine == "athena":
            def _check_athena():
                try:
                    client = boto3.client("athena", region_name=region)
                    # List work groups as a lightweight permission check
                    client.list_work_groups()
                except ClientError as e:
                    return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
                except Exception as e:
                    return str(e)
                return None

            checks.append(("athena:ListWorkGroups (proxy for Athena access)",
                            _check_athena))

    # --- CloudWatch permissions (when CW source is used) ---
    if log_group:
        def _check_cw_describe():
            try:
                client = boto3.client("logs", region_name=region)
                resp = client.describe_log_groups(
                    logGroupNamePrefix=log_group, limit=1)
                groups = resp.get("logGroups", [])
                if not any(g["logGroupName"] == log_group for g in groups):
                    return (f"Log group '{log_group}' not found. "
                            "Verify the name and region.")
            except ClientError as e:
                return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
            except Exception as e:
                return str(e)
            return None

        checks.append((f"logs:DescribeLogGroups (group: {log_group})",
                        _check_cw_describe))

    # --- Pricing permissions (optional) ---
    if with_pricing:
        def _check_pricing():
            try:
                client = boto3.client("pricing", region_name="us-east-1")
                client.describe_services(ServiceCode="AmazonBedrock",
                                         MaxResults=1)
            except ClientError as e:
                return f"{e.response['Error']['Code']}: {e.response['Error']['Message']}"
            except Exception as e:
                return str(e)
            return None

        checks.append(("pricing:DescribeServices (proxy for Pricing API)",
                        _check_pricing))

    # --- Run all checks ---
    all_passed = True
    warnings = []

    for desc, test_fn in checks:
        err = test_fn()
        if err is None:
            print(f"  PASS  {desc}")
        else:
            is_optional = desc.startswith("pricing:")
            if is_optional:
                print(f"  WARN  {desc}")
                warnings.append((desc, err))
            else:
                print(f"  FAIL  {desc}")
                print(f"        -> {err}", file=sys.stderr)
                all_passed = False

    print()
    for desc, err in warnings:
        print(f"  Warning ({desc}): {err}", file=sys.stderr)
        print(f"  Pricing data will use fallback values.", file=sys.stderr)

    if not all_passed:
        # Build the full list of IAM permissions needed for this run
        required = [
            "sts:GetCallerIdentity",
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:GetInferenceProfile",
            "bedrock:ListInferenceProfiles",
            "bedrock:ListFoundationModels",
            "iam:ListUsers",
            "iam:ListServiceSpecificCredentials",
        ]
        if s3_bucket:
            required.append("s3:GetObject")
            required.append("s3:ListBucket")
        if s3_bucket and engine == "athena":
            required.append("athena:StartQueryExecution")
            required.append("athena:GetQueryExecution")
            required.append("athena:GetQueryResults")
            required.append("s3:GetBucketLocation")
            required.append("s3:PutObject")
        if log_group:
            required.append("logs:DescribeLogGroups")
            required.append("logs:StartQuery")
            required.append("logs:GetQueryResults")
        if with_pricing:
            required.append("pricing:GetProducts")

        perms_list = "\n".join(f"    - {p}" for p in required)
        print(
            f"\nError: Missing required IAM permissions. "
            f"Ensure the caller has the following permissions and retry:\n"
            f"\n{perms_list}\n",
            file=sys.stderr,
        )

    return all_passed


# ---------------------------------------------------------------------------
# Logging Config Detection
# ---------------------------------------------------------------------------

def detect_logging_config(bedrock_client, args) -> dict:
    """Auto-detect S3 and CloudWatch logging targets via
    GetModelInvocationLoggingConfiguration, then let the user choose the
    log source when both are available and no CLI overrides narrow it down.

    Returns dict with keys: s3_bucket, s3_prefix, log_group.
    Raises SystemExit if Bedrock logging is not configured.
    """
    config = {"s3_bucket": None, "s3_prefix": None, "log_group": None}

    # --- Detect configured logging targets ---
    try:
        resp = bedrock_client.get_model_invocation_logging_configuration()
        logging_config = resp.get("loggingConfig", {})

        s3_config = logging_config.get("s3Config", {})
        if s3_config:
            config["s3_bucket"] = s3_config.get("bucketName")
            config["s3_prefix"] = s3_config.get("keyPrefix", "")

        cw_config = logging_config.get("cloudWatchConfig", {})
        if cw_config:
            config["log_group"] = cw_config.get("logGroupName")
    except Exception as e:
        print(f"Warning: could not auto-detect logging config: {e}",
              file=sys.stderr)

    # --- CLI overrides take precedence ---
    if args.s3_bucket:
        config["s3_bucket"] = args.s3_bucket
    if args.s3_prefix is not None:
        config["s3_prefix"] = args.s3_prefix
    if args.cw_log_group:
        config["log_group"] = args.cw_log_group

    has_s3 = bool(config["s3_bucket"])
    has_cw = bool(config["log_group"])
    cli_overridden = bool(args.s3_bucket or args.cw_log_group)

    # --- No logging configured at all ---
    if not has_s3 and not has_cw:
        print(
            "Error: Bedrock model invocation logging is not configured.\n"
            "No S3 bucket or CloudWatch log group detected, and no overrides "
            "provided.\n"
            "Enable logging in the Bedrock console or provide "
            "--s3-bucket/--s3-prefix or --cw-log-group arguments.",
            file=sys.stderr,
        )
        sys.exit(1)

    # --- If CLI args already narrow the source, use as-is ---
    if cli_overridden:
        return config

    # --- Both sources available: prompt user to choose ---
    if has_s3 and has_cw:
        print("\nBedrock logging is configured for both S3 and CloudWatch:")
        print(f"  S3:         s3://{config['s3_bucket']}/{config['s3_prefix']}")
        print(f"  CloudWatch: {config['log_group']}")
        print()
        print("Choose a log source:")
        print("  1) Load logs from CloudWatch Logs & Amazon S3 (merge both)")
        print("  2) Load logs from Amazon S3 only")
        print()

        while True:
            try:
                choice = input("Enter choice [1/2] (default: 1): ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.", file=sys.stderr)
                sys.exit(1)

            if choice in ("", "1"):
                # Keep both sources
                break
            elif choice == "2":
                # S3 only — clear CloudWatch
                config["log_group"] = None
                break
            else:
                print("  Invalid choice. Enter 1 or 2.")

    return config


# ---------------------------------------------------------------------------
# Identity Resolution
# ---------------------------------------------------------------------------

def parse_iam_identity(arn: str) -> str:
    """Extract human-readable identity from ARN.

    arn:aws:iam::ACCT:user/BedrockAPIKey-55zi    -> BedrockAPIKey-55zi
    arn:aws:sts::ACCT:assumed-role/ROLE/SESSION   -> ROLE/SESSION
    arn:aws:iam::ACCT:root                        -> root(ACCT)
    unknown                                        -> unknown
    """
    if not arn or arn == "unknown":
        return "unknown"
    if ":user/" in arn:
        return arn.split(":user/")[-1]
    if ":assumed-role/" in arn:
        return arn.split(":assumed-role/")[-1]
    if ":root" in arn:
        parts = arn.split(":")
        account = parts[4] if len(parts) > 4 else "unknown"
        return f"root({account})"
    return arn


def get_api_key_map(iam_client) -> dict[str, list[str]]:
    """Map IAM username -> list of ServiceSpecificCredentialId values.

    Iterates all IAM users, calls list_service_specific_credentials
    for bedrock.amazonaws.com.
    """
    mapping: dict[str, list[str]] = {}
    try:
        paginator = iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                try:
                    resp = iam_client.list_service_specific_credentials(
                        UserName=uname,
                        ServiceName="bedrock.amazonaws.com",
                    )
                    for c in resp.get("ServiceSpecificCredentials", []):
                        mapping.setdefault(uname, []).append(
                            c["ServiceSpecificCredentialId"]
                        )
                except Exception:
                    continue
    except Exception as e:
        print(f"Warning: could not load API key map: {e}", file=sys.stderr)
    return mapping


def should_include_identity(username: str,
                            bedrock_apikey_only: bool) -> bool:
    """Return True if this identity should appear in output.

    When bedrock_apikey_only=True: include only usernames starting with
    'BedrockAPIKey-'.
    When False: include all identities.
    """
    if bedrock_apikey_only:
        return username.startswith("BedrockAPIKey-")
    return True


# ---------------------------------------------------------------------------
# Model Resolution
# ---------------------------------------------------------------------------

_profile_cache: dict[str, tuple[str, bool, str]] = {}


def resolve_model_id(raw_model_id: str, bedrock_client) -> tuple[str, bool, str]:
    """Resolve raw modelId to (display_model_id, is_global_inference, app_profile_name).

    Handles application inference profile ARNs, system profile ARNs,
    and direct model IDs. Preserves 'global.' prefix, strips 'us./eu./ap.'.
    Uses an in-memory cache to avoid repeated API calls.
    """
    if raw_model_id in _profile_cache:
        return _profile_cache[raw_model_id]

    result = _resolve_model_id_inner(raw_model_id, bedrock_client)
    _profile_cache[raw_model_id] = result
    return result


def _resolve_model_id_inner(raw_model_id: str, bedrock_client) -> tuple[str, bool, str]:
    if ":application-inference-profile/" in raw_model_id:
        profile_id = raw_model_id.split(":application-inference-profile/")[-1]
        try:
            resp = bedrock_client.get_inference_profile(
                inferenceProfileIdentifier=profile_id
            )
            app_name = resp.get("inferenceProfileName", profile_id)
            models = resp.get("models", [])
            if models:
                model_arn = models[0]["modelArn"]
                foundation_id = model_arn.split("/")[-1]
                is_global = any("bedrock:::" in m["modelArn"] for m in models)
                if is_global:
                    return f"global.{foundation_id}", True, app_name
                return foundation_id, False, app_name
        except Exception as e:
            print(f"Warning: could not resolve inference profile "
                  f"'{profile_id}': {e}", file=sys.stderr)
        return raw_model_id, False, ""

    if ":inference-profile/" in raw_model_id:
        profile_id = raw_model_id.split(":inference-profile/")[-1]
        parts = profile_id.split(".", 1)
        if len(parts) == 2 and parts[0] in ("us", "eu", "ap"):
            return parts[1], False, ""
        if len(parts) == 2 and parts[0] == "global":
            return profile_id, True, ""
        return profile_id, False, ""

    # Direct model ID
    parts = raw_model_id.split(".", 1)
    if len(parts) == 2 and parts[0] in ("us", "eu", "ap"):
        return parts[1], False, ""
    if len(parts) == 2 and parts[0] == "global":
        return raw_model_id, True, ""
    return raw_model_id, False, ""


def build_profile_lookup(bedrock_client, region: str) -> dict:
    """Build inference profile ID -> {profile_name, model_id} mapping."""
    lookup = {}

    next_token = None
    while True:
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        try:
            resp = bedrock_client.list_inference_profiles(**kwargs)
        except Exception:
            break
        for p in resp.get("inferenceProfileSummaries", []):
            pid = p["inferenceProfileId"]
            models = p.get("models", [])
            base_model = (models[0].get("modelArn", "").split("/")[-1]
                          if models else pid)
            lookup[pid] = {"profile_name": pid, "model_id": base_model}
        next_token = resp.get("nextToken")
        if not next_token:
            break

    try:
        resp = bedrock_client.list_foundation_models()
        for m in resp.get("modelSummaries", []):
            mid = m["modelId"]
            if mid not in lookup:
                lookup[mid] = {"profile_name": "", "model_id": mid}
    except Exception:
        pass

    return lookup


# ---------------------------------------------------------------------------
# S3 Direct Engine
# ---------------------------------------------------------------------------

def generate_daily_prefixes(prefix: str, start_date: str, end_date: str) -> list[str]:
    """Generate S3 prefixes for each day in the date range."""
    prefixes = []
    current = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")
    while current <= end:
        daily_prefix = f"{prefix}{current.strftime('%Y/%m/%d')}/"
        prefixes.append(daily_prefix)
        current += timedelta(days=1)
    return prefixes


def list_log_files_for_prefix(bucket: str, prefix: str) -> list[str]:
    """List main log .json.gz files under one prefix, excluding /data/ files."""
    s3_client = boto3.client("s3")
    log_keys = []
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if "/data/" in key:
                continue
            if key.endswith("-permission-check"):
                continue
            if key.endswith(".json.gz"):
                log_keys.append(key)
    return log_keys


def list_log_files(bucket: str, daily_prefixes: list[str],
                   workers: int = LIST_WORKERS) -> list[str]:
    """List all main log files across daily prefixes using concurrent listing."""
    all_keys = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(list_log_files_for_prefix, bucket, p): p
            for p in daily_prefixes
        }
        listed = 0
        for future in as_completed(futures):
            listed += 1
            if listed % 20 == 0 or listed == len(daily_prefixes):
                print(f"  Listed {listed}/{len(daily_prefixes)} days...",
                      end="\r")
            try:
                all_keys.extend(future.result())
            except Exception as e:
                print(f"  Warning: Failed to list {futures[future]}: {e}",
                      file=sys.stderr)
    print()
    return all_keys


def download_and_parse(s3_client, bucket: str, key: str) -> list[dict]:
    """Download a .json.gz file from S3, decompress, and parse JSON records."""
    records = []
    try:
        response = s3_client.get_object(Bucket=bucket, Key=key)
        compressed = response["Body"].read()
        decompressed = gzip.decompress(compressed).decode("utf-8")

        for line in decompressed.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                records.append(record)
            except json.JSONDecodeError:
                continue

        if not records:
            try:
                record = json.loads(decompressed)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                pass
    except Exception as e:
        print(f"  Warning: Failed to process {key}: {e}", file=sys.stderr)
    return records


def extract_token_data(record: dict) -> tuple[str, str, int, int, int, int]:
    """Extract identity ARN, raw modelId, and token counts from a log record.

    Returns (identity_arn, raw_model_id, input_tokens, output_tokens,
             cache_read, cache_write).
    """
    identity_arn = (record.get("identity", {}).get("arn", "unknown")
                    if record.get("identity") else "unknown")
    raw_model_id = record.get("modelId", "unknown")

    inp = record.get("input", {})
    out = record.get("output", {})

    input_tokens = inp.get("inputTokenCount", 0) or 0
    output_tokens = out.get("outputTokenCount", 0) or 0
    cache_read = inp.get("cacheReadInputTokenCount", 0) or 0
    cache_write = inp.get("cacheWriteInputTokenCount", 0) or 0

    return identity_arn, raw_model_id, input_tokens, output_tokens, cache_read, cache_write


def run_s3_engine(s3_client, bucket: str, prefix: str, start_date: str,
                  end_date: str, workers: int) -> dict[tuple[str, str], dict]:
    """Query logs via direct S3 download + concurrent Python processing.

    Returns {(identity_arn, raw_model_id): {request_count, input_tokens,
    output_tokens, cache_read, cache_write}}.
    Note: request_count is set to None for S3 direct engine (individual record
    counting is not aggregated).
    """
    print("[Engine: S3 Direct]\n")

    daily_prefixes = generate_daily_prefixes(prefix, start_date, end_date)
    print(f"Generating S3 prefixes: {len(daily_prefixes)} days to scan")

    print("Listing log files in S3...")
    log_keys = list_log_files(bucket, daily_prefixes, workers=LIST_WORKERS)
    print(f"  Found {len(log_keys)} main log files")

    if not log_keys:
        return {}

    print(f"Downloading and parsing logs ({workers} threads)...")
    usage = defaultdict(lambda: {
        "request_count": None, "input_tokens": 0, "output_tokens": 0,
        "cache_read": 0, "cache_write": 0,
    })
    total_records = 0
    errors = 0

    _thread_local = threading.local()

    def process_key(key):
        if not hasattr(_thread_local, "s3"):
            _thread_local.s3 = boto3.client("s3")
        return download_and_parse(_thread_local.s3, bucket, key)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(process_key, k): k for k in log_keys}
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0 or completed == len(log_keys):
                print(f"  Processed {completed}/{len(log_keys)} files...",
                      end="\r")
            try:
                records = future.result()
                for record in records:
                    arn, raw_mid, inp_tok, out_tok, c_read, c_write = (
                        extract_token_data(record))
                    k = (arn, raw_mid)
                    usage[k]["input_tokens"] += inp_tok
                    usage[k]["output_tokens"] += out_tok
                    usage[k]["cache_read"] += c_read
                    usage[k]["cache_write"] += c_write
                    total_records += 1
            except Exception as e:
                print(f"  Warning: Failed to process {futures[future]}: {e}",
                      file=sys.stderr)
                errors += 1

    print(f"\n  Total records processed: {total_records}")
    if errors:
        print(f"  Files with errors: {errors}")
    print()
    return dict(usage)


# ---------------------------------------------------------------------------
# Athena Engine
# ---------------------------------------------------------------------------

_S3_BUCKET_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{1,61}[a-zA-Z0-9]$')
_S3_PREFIX_RE = re.compile(r'^[a-zA-Z0-9_.!/\-]*$')


def _validate_s3_location(bucket: str, prefix: str):
    """Validate bucket and prefix to prevent injection in Athena DDL."""
    if not _S3_BUCKET_RE.match(bucket):
        print(f"Error: invalid S3 bucket name '{bucket}'. "
              "Bucket names must match [a-zA-Z0-9][a-zA-Z0-9.\\-]{{1,61}}"
              "[a-zA-Z0-9].", file=sys.stderr)
        sys.exit(1)
    if prefix and not _S3_PREFIX_RE.match(prefix):
        print(f"Error: invalid S3 prefix '{prefix}'. "
              "Prefix must contain only alphanumerics, '.', '_', '!', '/', "
              "and '-'.", file=sys.stderr)
        sys.exit(1)
    if "'" in bucket or "'" in prefix:
        print("Error: S3 bucket or prefix must not contain single quotes.",
              file=sys.stderr)
        sys.exit(1)


def athena_run_query(athena_client, query: str, output_location: str,
                     description: str = "") -> str:
    """Execute an Athena query and wait for completion. Returns query ID."""
    if description:
        print(f"  {description}...", end=" ", flush=True)

    response = athena_client.start_query_execution(
        QueryString=query,
        ResultConfiguration={"OutputLocation": output_location},
    )
    query_id = response["QueryExecutionId"]

    deadline = time.monotonic() + ATHENA_QUERY_TIMEOUT_SEC
    while True:
        result = athena_client.get_query_execution(QueryExecutionId=query_id)
        state = result["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        if time.monotonic() > deadline:
            if description:
                print("TIMEOUT")
            print(f"Error: Athena query timed out after "
                  f"{ATHENA_QUERY_TIMEOUT_SEC}s (queryId={query_id}).",
                  file=sys.stderr)
            sys.exit(1)
        time.sleep(1)

    if state != "SUCCEEDED":
        reason = result["QueryExecution"]["Status"].get(
            "StateChangeReason", "unknown")
        if description:
            print("FAILED")
        print(f"Error: Athena query {state}: {reason}", file=sys.stderr)
        sys.exit(1)

    if description:
        stats = result["QueryExecution"].get("Statistics", {})
        scanned_mb = stats.get("DataScannedInBytes", 0) / (1024 * 1024)
        exec_ms = stats.get("EngineExecutionTimeInMillis", 0)
        print(f"OK ({exec_ms}ms, {scanned_mb:.2f} MB scanned)")

    return query_id


def athena_get_results(athena_client, query_id: str) -> list[list[str]]:
    """Fetch all result rows from a completed Athena query."""
    rows = []
    paginator = athena_client.get_paginator("get_query_results")
    first_page = True
    for page in paginator.paginate(QueryExecutionId=query_id):
        for row in page["ResultSet"]["Rows"]:
            if first_page:
                first_page = False
                continue  # skip header row
            rows.append([col.get("VarCharValue", "") for col in row["Data"]])
    return rows


def athena_ensure_database(athena_client, output_location: str):
    """Create the Athena database if it doesn't exist."""
    athena_run_query(
        athena_client,
        f"CREATE DATABASE IF NOT EXISTS {ATHENA_DATABASE}",
        output_location,
        description=f"Creating database '{ATHENA_DATABASE}'",
    )


def athena_ensure_table(athena_client, bucket: str, prefix: str,
                        output_location: str):
    """Create the Athena table with partition projection."""
    _validate_s3_location(bucket, prefix)
    athena_run_query(
        athena_client,
        f"DROP TABLE IF EXISTS {ATHENA_DATABASE}.{ATHENA_TABLE}",
        output_location,
        description=f"Dropping existing table '{ATHENA_TABLE}'",
    )

    s3_location = f"s3://{bucket}/{prefix}"
    create_ddl = f"""
    CREATE EXTERNAL TABLE {ATHENA_DATABASE}.{ATHENA_TABLE} (
        `timestamp` string,
        accountId string,
        region string,
        requestId string,
        operation string,
        modelId string,
        identity struct<arn:string>,
        input struct<
            inputContentType:string,
            inputTokenCount:bigint,
            cacheReadInputTokenCount:bigint,
            cacheWriteInputTokenCount:bigint
        >,
        output struct<
            outputContentType:string,
            outputTokenCount:bigint
        >,
        inferenceRegion string,
        schemaType string,
        schemaVersion string
    )
    PARTITIONED BY (year string, month string, day string, hour string)
    ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
    WITH SERDEPROPERTIES ('ignore.malformed.json' = 'true')
    STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.IgnoreKeyTextOutputFormat'
    LOCATION '{s3_location}'
    TBLPROPERTIES (
        'projection.enabled' = 'true',
        'projection.year.type' = 'integer',
        'projection.year.range' = '2023,2030',
        'projection.year.digits' = '4',
        'projection.month.type' = 'integer',
        'projection.month.range' = '1,12',
        'projection.month.digits' = '2',
        'projection.day.type' = 'integer',
        'projection.day.range' = '1,31',
        'projection.day.digits' = '2',
        'projection.hour.type' = 'integer',
        'projection.hour.range' = '0,23',
        'projection.hour.digits' = '2',
        'storage.location.template' = '{s3_location}${{year}}/${{month}}/${{day}}/${{hour}}'
    )
    """
    athena_run_query(
        athena_client,
        create_ddl,
        output_location,
        description=f"Creating table '{ATHENA_TABLE}' with partition projection",
    )


def run_athena_engine(athena_client, bucket: str, prefix: str,
                      start_date: str, end_date: str,
                      athena_output: str) -> dict[tuple[str, str], dict]:
    """Query logs via Athena SQL with automatic table setup and partition
    projection. Same return shape as run_s3_engine."""
    print("[Engine: Athena]\n")

    output_location = athena_output or f"s3://{bucket}/{ATHENA_OUTPUT_PREFIX}"

    print("Setting up Athena resources...")
    athena_ensure_database(athena_client, output_location)
    athena_ensure_table(athena_client, bucket, prefix, output_location)

    start = datetime.strptime(start_date, "%Y-%m-%d")
    end = datetime.strptime(end_date, "%Y-%m-%d")

    date_filter = (
        f"CAST(year AS INTEGER) * 10000 + CAST(month AS INTEGER) * 100 "
        f"+ CAST(day AS INTEGER) "
        f"BETWEEN {start.year * 10000 + start.month * 100 + start.day} "
        f"AND {end.year * 10000 + end.month * 100 + end.day}"
    )

    query = f"""
    SELECT
        COALESCE(identity.arn, 'unknown') AS identity_arn,
        COALESCE(modelId, 'unknown') AS raw_model_id,
        COUNT(*) AS request_count,
        COALESCE(SUM(input.inputTokenCount), 0) AS input_tokens,
        COALESCE(SUM(output.outputTokenCount), 0) AS output_tokens,
        COALESCE(SUM(input.cacheReadInputTokenCount), 0) AS cache_read,
        COALESCE(SUM(input.cacheWriteInputTokenCount), 0) AS cache_write
    FROM {ATHENA_DATABASE}.{ATHENA_TABLE}
    WHERE {date_filter}
        AND "$path" NOT LIKE '%/data/%'
        AND "$path" LIKE '%.json.gz'
        AND "$path" NOT LIKE '%permission-check%'
    GROUP BY COALESCE(identity.arn, 'unknown'), COALESCE(modelId, 'unknown')
    ORDER BY identity_arn, raw_model_id
    """

    print("\nRunning aggregation query...")
    query_id = athena_run_query(
        athena_client, query, output_location,
        description="Querying token usage",
    )

    rows = athena_get_results(athena_client, query_id)
    print(f"  {len(rows)} identity + model combinations found\n")

    usage = {}
    for row in rows:
        identity_arn, raw_model_id, req_count = row[0], row[1], row[2]
        inp_tok, out_tok, c_read, c_write = row[3], row[4], row[5], row[6]
        usage[(identity_arn, raw_model_id)] = {
            "request_count": int(req_count),
            "input_tokens": int(inp_tok),
            "output_tokens": int(out_tok),
            "cache_read": int(c_read),
            "cache_write": int(c_write),
        }
    return usage


# ---------------------------------------------------------------------------
# CloudWatch Engine
# ---------------------------------------------------------------------------

def run_cloudwatch_engine(logs_client, log_group: str,
                          start: datetime, end: datetime
                          ) -> dict[tuple[str, str], dict]:
    """Query CloudWatch Logs Insights for token usage grouped by
    identity ARN + modelId.

    Uses 'stats count(*) as requestCount, sum(...)' to include request counts.
    Returns same shape as S3/Athena engines.
    """
    print("[Engine: CloudWatch Logs Insights]\n")

    query = """\
fields @timestamp, identity.arn, modelId,
       input.inputTokenCount, output.outputTokenCount,
       input.cacheReadInputTokenCount, input.cacheWriteInputTokenCount
| filter ispresent(modelId)
| stats count(*) as requestCount,
        sum(input.inputTokenCount) as inputTokens,
        sum(output.outputTokenCount) as outputTokens,
        sum(input.cacheReadInputTokenCount) as cacheReadInputTokens,
        sum(input.cacheWriteInputTokenCount) as cacheWriteInputTokens
  by identity.arn, modelId
| sort inputTokens desc
"""

    print(f"  Querying log group: {log_group}")
    print(f"  Time range: {start.isoformat()} to {end.isoformat()}")

    resp = logs_client.start_query(
        logGroupName=log_group,
        startTime=int(start.timestamp()),
        endTime=int(end.timestamp()),
        queryString=query,
    )
    qid = resp["queryId"]

    deadline = time.monotonic() + CW_QUERY_TIMEOUT_SEC
    while True:
        result = logs_client.get_query_results(queryId=qid)
        status = result["status"]
        if status == "Complete":
            break
        if status in ("Failed", "Cancelled", "Timeout"):
            print(f"Error: CloudWatch Logs Insights query {status.lower()} "
                  f"(queryId={qid}).", file=sys.stderr)
            sys.exit(1)
        if time.monotonic() > deadline:
            print(f"Error: CloudWatch Logs Insights query timed out after "
                  f"{CW_QUERY_TIMEOUT_SEC}s (queryId={qid}).",
                  file=sys.stderr)
            sys.exit(1)
        time.sleep(1)

    usage = {}
    for record in result.get("results", []):
        row = {f["field"]: f["value"] for f in record}
        identity_arn = row.get("identity.arn", "unknown")
        raw_model_id = row.get("modelId", "unknown")
        usage[(identity_arn, raw_model_id)] = {
            "request_count": int(float(row.get("requestCount", 0))),
            "input_tokens": int(float(row.get("inputTokens", 0))),
            "output_tokens": int(float(row.get("outputTokens", 0))),
            "cache_read": int(float(row.get("cacheReadInputTokens", 0))),
            "cache_write": int(float(row.get("cacheWriteInputTokens", 0))),
        }

    print(f"  {len(usage)} identity + model combinations found\n")
    return usage


# ---------------------------------------------------------------------------
# Data Merge
# ---------------------------------------------------------------------------

def merge_usage(s3_usage: dict[tuple, dict] | None,
                cw_usage: dict[tuple, dict] | None
                ) -> dict[tuple[str, str], dict]:
    """Merge S3/Athena and CloudWatch results. S3 data is primary.

    Strategy:
    - Start with all S3/Athena entries.
    - For each CloudWatch key not present in S3 data: ADD it.
    - If only one source is available, return it directly.
    """
    if s3_usage and not cw_usage:
        return s3_usage
    if cw_usage and not s3_usage:
        return cw_usage
    if not s3_usage and not cw_usage:
        return {}

    merged = dict(s3_usage)
    for key, data in cw_usage.items():
        if key not in merged:
            merged[key] = data
    return merged


# ---------------------------------------------------------------------------
# Pricing
# ---------------------------------------------------------------------------

_pricing_mem_cache: dict[str, dict] = {}


def _pricing_cache_path(region: str) -> Path:
    return Path(__file__).parent / f"amazon-bedrock-pricing-cache-{region}.json"


def _fetch_pricing_from_aws(region: str) -> dict[str, dict[str, float]]:
    """Call the AWS Pricing API and return parsed pricing data."""
    location = REGION_TO_LOCATION.get(region)
    if not location:
        print(f"Warning: no Pricing API location mapping for region '{region}'. "
              "Using fallback pricing only.", file=sys.stderr)
        return {}

    pricing_client = boto3.client("pricing", region_name="us-east-1")
    result: dict[str, dict[str, float]] = {}

    try:
        paginator = pricing_client.get_paginator("get_products")
        pages = paginator.paginate(
            ServiceCode="AmazonBedrock",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "location", "Value": location},
                {"Type": "TERM_MATCH", "Field": "feature",
                 "Value": "On-demand Inference"},
            ],
        )
        for page in pages:
            for item_str in page["PriceList"]:
                item = json.loads(item_str)
                attrs = item.get("product", {}).get("attributes", {})
                model_name = attrs.get("model", "")
                inf_type = attrs.get("inferenceType", "")

                price_key = _INF_TYPE_MAP.get(inf_type)
                if not price_key:
                    continue
                model_prefix = _PRICING_MODEL_NAME_TO_ID.get(model_name)
                if not model_prefix:
                    continue

                for term_data in item.get("terms", {}).values():
                    for sku_data in term_data.values():
                        for dim_data in sku_data.get("priceDimensions",
                                                     {}).values():
                            usd = float(dim_data.get("pricePerUnit",
                                                     {}).get("USD", "0"))
                            result.setdefault(model_prefix, {
                                "input": 0.0, "output": 0.0,
                                "cache_read": 0.0, "cache_write": 0.0,
                            })[price_key] = usd
    except Exception as e:
        print(f"Warning: Pricing API call failed: {e}. Using fallback pricing.",
              file=sys.stderr)

    return result


def fetch_pricing(region: str) -> dict[str, dict[str, float]]:
    """Get Bedrock pricing for a region with 3-tier cache.

    Lookup order:
        1. In-memory dict (_pricing_mem_cache)
        2. Local file cache: amazon-bedrock-pricing-cache-{region}.json (< 1 day old)
        3. AWS Pricing API (GetProducts for AmazonBedrock service)
    """
    if region in _pricing_mem_cache:
        return _pricing_mem_cache[region]

    # Try file cache
    path = _pricing_cache_path(region)
    try:
        if path.exists():
            with open(path) as f:
                cached = json.load(f)
            metadata = cached.get("metadata", {})
            fetched_at = metadata.get("fetched_at", "")
            if fetched_at:
                fetched_time = datetime.fromisoformat(
                    fetched_at.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) - fetched_time < timedelta(
                        hours=24):
                    api_pricing = cached.get("api_pricing", {})
                    _pricing_mem_cache[region] = api_pricing
                    return api_pricing
    except (OSError, json.JSONDecodeError, ValueError):
        pass

    # Fetch from AWS
    result = _fetch_pricing_from_aws(region)

    # Save to file cache
    try:
        cache_data = {
            "metadata": {
                "region": region,
                "location": REGION_TO_LOCATION.get(region, ""),
                "fetched_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "ttl_hours": 24,
            },
            "api_pricing": result,
            "fallback_pricing": {
                pattern: prices
                for pattern, prices in FALLBACK_PRICING
            },
        }
        with open(path, "w") as f:
            json.dump(cache_data, f, indent=2)
    except OSError as e:
        print(f"Warning: could not write pricing cache: {e}", file=sys.stderr)

    _pricing_mem_cache[region] = result
    return result


def get_model_pricing(display_model_id: str, region: str
                      ) -> dict[str, float] | None:
    """Get per-1K-token pricing for a specific model.

    Strips 'global.' prefix for API lookup, then tries FALLBACK_PRICING
    regex match. Returns None if pricing is unavailable.
    """
    lookup_id = display_model_id
    if lookup_id.startswith("global."):
        lookup_id = lookup_id[len("global."):]

    prices = None
    api_prices = fetch_pricing(region)

    for prefix, p in api_prices.items():
        if lookup_id.startswith(prefix):
            prices = p
            break

    if prices is None:
        for pattern, p in FALLBACK_PRICING:
            if re.search(pattern, display_model_id):
                prices = p
                break

    return prices


def compute_costs(tokens: dict, pricing: dict[str, float]) -> dict[str, float]:
    """Calculate USD costs from token counts and per-1K-token prices."""
    input_cost = tokens["input_tokens"] / 1000.0 * pricing["input"]
    output_cost = tokens["output_tokens"] / 1000.0 * pricing["output"]
    cache_read_cost = tokens["cache_read"] / 1000.0 * pricing["cache_read"]
    cache_write_cost = tokens["cache_write"] / 1000.0 * pricing["cache_write"]
    total_cost = input_cost + output_cost + cache_read_cost + cache_write_cost
    return {
        "input_cost": input_cost,
        "output_cost": output_cost,
        "cache_read_cost": cache_read_cost,
        "cache_write_cost": cache_write_cost,
        "total_cost": total_cost,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def build_enriched_rows(usage: dict, api_key_map: dict, bedrock_client,
                        region: str,
                        bedrock_apikey_only: bool,
                        with_pricing: bool) -> list[dict]:
    """Transform raw usage dict into enriched output rows.

    For each (identity_arn, raw_model_id) entry:
        1. Parse identity -> IAM_User
        2. Look up API_Key_IDs from api_key_map
        3. Resolve model -> (display_model_id, is_global, app_profile_name)
        4. Filter by bedrock_apikey_only
        5. Optionally compute costs
        6. Calculate Total_Tokens
    """
    rows = []
    sorted_keys = sorted(usage.keys(), key=lambda k: (k[0], k[1]))

    for identity_arn, raw_model_id in sorted_keys:
        data = usage[(identity_arn, raw_model_id)]
        username = parse_iam_identity(identity_arn)

        if not should_include_identity(username, bedrock_apikey_only):
            continue

        key_ids = api_key_map.get(username, [])
        display_model_id, _, app_profile_name = resolve_model_id(
            raw_model_id, bedrock_client)
        total_tokens = (data["input_tokens"] + data["output_tokens"]
                        + data["cache_read"] + data["cache_write"])

        row = {
            "IAM_User": username,
            "API_Key_IDs": ",".join(key_ids),
            "App_Profile": app_profile_name,
            "Model_ID": display_model_id,
            "Request_count": data.get("request_count"),
            "Input_Tokens": data["input_tokens"],
            "Output_Tokens": data["output_tokens"],
            "CacheRead_Tokens": data["cache_read"],
            "CacheWrite_Tokens": data["cache_write"],
            "Total_Tokens": total_tokens,
        }

        if with_pricing:
            pricing = get_model_pricing(display_model_id, region) \
                if key_ids else None

            if pricing is not None:
                costs = compute_costs(data, pricing)
                row.update({
                    "Input_Cost_USD": costs["input_cost"],
                    "Output_Cost_USD": costs["output_cost"],
                    "CacheRead_Cost_USD": costs["cache_read_cost"],
                    "CacheWrite_Cost_USD": costs["cache_write_cost"],
                    "Total_Cost_USD": costs["total_cost"],
                })
            else:
                row.update({
                    "Input_Cost_USD": None,
                    "Output_Cost_USD": None,
                    "CacheRead_Cost_USD": None,
                    "CacheWrite_Cost_USD": None,
                    "Total_Cost_USD": None,
                })

        rows.append(row)

    return rows


def _format_cost_csv(value) -> str:
    """Format cost value for CSV output."""
    if value is None:
        return ""
    if value == 0:
        return "0"
    return f"{value:.4f}"


def write_csv(rows: list[dict], output_path: str, with_pricing: bool):
    """Write enriched rows to CSV file.

    Columns always present:
        IAM_User, API_Key_IDs, App_Profile, Model_ID, Request_count,
        Input_Tokens, Output_Tokens, CacheRead_Tokens, CacheWrite_Tokens,
        Total_Tokens

    Additional columns when with_pricing=true:
        Input_Cost_USD, Output_Cost_USD, CacheRead_Cost_USD,
        CacheWrite_Cost_USD, Total_Cost_USD
    """
    columns = [
        "IAM_User", "API_Key_IDs", "App_Profile", "Model_ID",
        "Request_count", "Input_Tokens", "Output_Tokens",
        "CacheRead_Tokens", "CacheWrite_Tokens", "Total_Tokens",
    ]
    if with_pricing:
        columns += [
            "Input_Cost_USD", "Output_Cost_USD",
            "CacheRead_Cost_USD", "CacheWrite_Cost_USD", "Total_Cost_USD",
        ]

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            csv_row = dict(row)
            # Format request_count: empty when None/0
            rc = csv_row.get("Request_count")
            csv_row["Request_count"] = rc if rc else ""
            # Format costs
            if with_pricing:
                for col in ["Input_Cost_USD", "Output_Cost_USD",
                            "CacheRead_Cost_USD", "CacheWrite_Cost_USD",
                            "Total_Cost_USD"]:
                    csv_row[col] = _format_cost_csv(csv_row.get(col))
            writer.writerow(csv_row)

    print(f"CSV report written to: {output_path}")


def write_txt(rows: list[dict], output_path: str, time_desc: str,
              region: str, with_pricing: bool):
    """Write enriched rows to formatted text file."""
    with open(output_path, "w") as f:
        title = ("Bedrock Token Consumption & Cost" if with_pricing
                 else "Bedrock Token Consumption")
        f.write(f"{title} per IAM User - {time_desc} "
                f"(region: {region})\n\n")
        for row in rows:
            parts = [
                f"IAM_User={row['IAM_User']}",
                f"Model={row['Model_ID']}",
                f"Input={row['Input_Tokens']}",
                f"Output={row['Output_Tokens']}",
                f"Total={row['Total_Tokens']}",
            ]
            if with_pricing and row.get("Total_Cost_USD") is not None:
                parts.append(f"Cost=${row['Total_Cost_USD']:.4f}")
            f.write("  ".join(parts) + "\n")
    print(f"Report written to: {output_path}")


def write_html(rows: list[dict], output_path: str, time_desc: str,
               region: str, with_pricing: bool):
    """Write an interactive HTML report with a React-based dynamic table.

    Embeds row data as a JSON variable and uses React + CDN to render a
    sortable, filterable table with per-user subtotals and a grand total.
    Includes a collapsible pricing reference section at the bottom.
    Everything is contained in a single self-contained HTML file.
    """
    # Prepare JSON-safe row data (None -> null handled by json.dumps)
    json_rows = []
    for row in rows:
        r = dict(row)
        # Round cost floats for cleaner display
        for cost_key in ("Input_Cost_USD", "Output_Cost_USD",
                         "CacheRead_Cost_USD", "CacheWrite_Cost_USD",
                         "Total_Cost_USD"):
            if cost_key in r and r[cost_key] is not None:
                r[cost_key] = round(r[cost_key], 4)
        json_rows.append(r)

    # Collect pricing for every unique model in the report
    pricing_ref = {}
    for row in rows:
        model_id = row.get("Model_ID", "")
        if model_id and model_id not in pricing_ref:
            prices = get_model_pricing(model_id, region)
            if prices:
                pricing_ref[model_id] = {
                    "input": prices["input"],
                    "output": prices["output"],
                    "cache_read": prices["cache_read"],
                    "cache_write": prices["cache_write"],
                }
            else:
                pricing_ref[model_id] = None

    data_json = json.dumps(json_rows, indent=2)
    pricing_json = json.dumps(pricing_ref, indent=2)
    title = ("Bedrock Token Consumption &amp; Cost" if with_pricing
             else "Bedrock Token Consumption")
    safe_time_desc = html_module.escape(time_desc)
    safe_title = html_module.escape(title)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{safe_title} - {safe_time_desc}</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg-primary: #0c1018;
    --bg-secondary: #131a28;
    --bg-card: #161e2e;
    --bg-table: #0f1525;
    --border-dim: #222d40;
    --border-glow: #4ac8d044;
    --cyan: #5bbcd6;
    --cyan-dim: #5bbcd630;
    --cyan-bright: #7ad0e4;
    --magenta: #c477db;
    --magenta-dim: #c477db30;
    --yellow: #d4c95a;
    --yellow-dim: #d4c95a44;
    --green: #5cd49a;
    --green-dim: #5cd49a44;
    --text-primary: #d8dff0;
    --text-secondary: #8e99b3;
    --text-dim: #586274;
  }}
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: 'Rajdhani', 'Segoe UI', sans-serif;
    margin: 0; padding: 24px;
    background: var(--bg-primary);
    color: var(--text-primary);
    min-height: 100vh;
  }}
  body::before {{
    content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background:
      repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(91,188,214,0.008) 2px, rgba(91,188,214,0.008) 4px),
      radial-gradient(ellipse at 20% 50%, rgba(91,188,214,0.025) 0%, transparent 60%),
      radial-gradient(ellipse at 80% 20%, rgba(196,119,219,0.018) 0%, transparent 60%);
    pointer-events: none; z-index: 0;
  }}
  #root {{ position: relative; z-index: 1; max-width: 1600px; margin: 0 auto; }}

  /* ── Header ── */
  .header {{
    position: relative;
    background: linear-gradient(135deg, #0a0e17 0%, #111827 50%, #0a0e17 100%);
    border: 1px solid var(--border-dim);
    border-radius: 16px; padding: 28px 36px; margin-bottom: 28px;
    overflow: hidden;
  }}
  .header::before {{
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--cyan), var(--magenta), transparent);
  }}
  .header::after {{
    content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, var(--cyan-dim), transparent);
  }}
  .header h1 {{
    margin: 0 0 10px 0; font-family: 'Orbitron', monospace;
    font-size: 1.75rem; font-weight: 700; letter-spacing: 0.08em;
    background: linear-gradient(90deg, var(--cyan), var(--magenta));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: none;
    filter: drop-shadow(0 0 6px var(--cyan-dim));
  }}
  .header .meta {{
    font-size: 0.95rem; color: var(--text-secondary);
    font-family: 'JetBrains Mono', monospace; letter-spacing: 0.04em;
  }}
  .header .meta .separator {{ color: var(--cyan-dim); margin: 0 8px; }}

  /* ── Summary Cards ── */
  .summary-cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border-dim);
    border-radius: 12px; padding: 18px 22px; min-width: 155px;
    position: relative; overflow: hidden;
    transition: border-color 0.3s, box-shadow 0.3s;
  }}
  .card:hover {{
    border-color: var(--cyan-dim);
    box-shadow: 0 0 12px var(--cyan-dim);
  }}
  .card::before {{
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--cyan), var(--magenta));
    opacity: 0.6;
  }}
  .card .label {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.75rem; color: var(--text-secondary);
    text-transform: uppercase; letter-spacing: 0.15em; margin-bottom: 6px;
  }}
  .card .value {{
    font-family: 'Orbitron', monospace; font-size: 1.4rem; font-weight: 700;
    color: var(--cyan-bright);
  }}
  .card .value.cost-val {{ color: var(--magenta); }}

  /* ── Controls ── */
  .controls {{
    display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap;
    align-items: center;
  }}
  .controls input, .controls select {{
    padding: 10px 14px;
    background: var(--bg-card); color: var(--text-primary);
    border: 1px solid var(--border-dim); border-radius: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 0.9rem;
    outline: none; transition: border-color 0.3s, box-shadow 0.3s;
  }}
  .controls input::placeholder {{ color: var(--text-dim); }}
  .controls input:focus, .controls select:focus {{
    border-color: var(--cyan); box-shadow: 0 0 8px var(--cyan-dim);
  }}
  .controls select option {{ background: var(--bg-secondary); color: var(--text-primary); }}
  .controls input {{ min-width: 280px; }}

  /* ── Table ── */
  .table-wrap {{
    overflow-x: auto; background: var(--bg-table);
    border: 1px solid var(--border-dim); border-radius: 12px;
    box-shadow: 0 0 20px rgba(0,0,0,0.3), inset 0 1px 0 rgba(91,188,214,0.03);
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; white-space: nowrap; }}
  thead th {{
    position: sticky; top: 0; z-index: 2;
    background: linear-gradient(180deg, #182030, #141c2a);
    padding: 12px 16px; text-align: left;
    font-family: 'JetBrains Mono', monospace; font-weight: 600;
    font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--cyan); border-bottom: 1px solid var(--cyan-dim);
    cursor: pointer; user-select: none;
    transition: color 0.2s, background 0.2s;
  }}
  thead th:hover {{ color: #dde6f0; background: linear-gradient(180deg, #1e2838, #182030); }}
  thead th .sort-icon {{ margin-left: 4px; opacity: 0.3; font-size: 0.75rem; }}
  thead th .sort-icon.active {{ opacity: 1; color: var(--magenta); }}
  tbody td {{
    padding: 10px 16px; border-bottom: 1px solid #1e2840;
    font-family: 'JetBrains Mono', monospace; font-size: 0.88rem;
    transition: background 0.15s;
  }}
  tbody tr {{ transition: background 0.15s; }}
  tbody tr:hover {{ background: rgba(91,188,214,0.04); }}
  tbody tr:hover td {{ border-bottom-color: var(--cyan-dim); }}
  tbody tr.subtotal {{
    background: linear-gradient(90deg, rgba(91,188,214,0.05), rgba(196,119,219,0.03));
    font-weight: 600;
  }}
  tbody tr.subtotal td {{
    border-bottom: 1px solid var(--cyan-dim); color: var(--cyan-bright);
    padding-top: 11px; padding-bottom: 11px;
  }}
  tfoot td {{
    padding: 12px 16px; font-weight: 700;
    background: linear-gradient(90deg, rgba(196,119,219,0.06), rgba(91,188,214,0.06));
    border-top: 1px solid var(--magenta-dim);
    font-family: 'Orbitron', monospace; font-size: 0.82rem;
    color: #dde6f0;
  }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .cost {{ text-align: right; font-variant-numeric: tabular-nums; color: var(--magenta); }}

  /* ── Pricing Section ── */
  .pricing-section {{ margin-top: 36px; }}
  .pricing-toggle {{
    display: flex; align-items: center; gap: 10px; cursor: pointer;
    background: var(--bg-card); border: 1px solid var(--border-dim);
    border-radius: 10px; padding: 14px 22px; width: 100%; text-align: left;
    font-family: 'Orbitron', monospace; font-size: 0.9rem; font-weight: 600;
    color: var(--text-secondary); letter-spacing: 0.06em;
    transition: border-color 0.3s, box-shadow 0.3s, color 0.3s;
  }}
  .pricing-toggle:hover {{
    border-color: var(--cyan-dim); color: var(--cyan);
    box-shadow: 0 0 8px var(--cyan-dim);
  }}
  .pricing-toggle .chevron {{
    transition: transform 0.3s; font-size: 0.8rem; color: var(--cyan);
  }}
  .pricing-toggle .chevron.open {{ transform: rotate(90deg); }}
  .pricing-body {{
    margin-top: 12px; background: var(--bg-table);
    border: 1px solid var(--border-dim); border-radius: 12px;
    overflow-x: auto;
    box-shadow: 0 0 14px rgba(0,0,0,0.25);
  }}
  .pricing-body table {{ font-size: 0.88rem; }}
  .pricing-body thead th {{
    background: linear-gradient(180deg, #182030, #141c2a);
    padding: 10px 16px; text-align: left;
    font-family: 'JetBrains Mono', monospace; font-weight: 600;
    font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.06em;
    color: var(--cyan); border-bottom: 1px solid var(--cyan-dim);
    cursor: default;
  }}
  .pricing-body thead th.num {{ text-align: right; }}
  .pricing-body tbody td {{
    padding: 9px 16px; border-bottom: 1px solid #1e2840;
    font-family: 'JetBrains Mono', monospace;
  }}
  .pricing-body tbody tr:hover {{ background: rgba(91,188,214,0.04); }}
  .pricing-na {{ color: var(--text-dim); font-style: italic; }}
  .pricing-unit {{
    font-size: 0.75rem; color: var(--text-dim); font-weight: 400;
    margin-left: 8px;
  }}

  /* ── Glow Keyframes ── */
  @keyframes pulse-glow {{
    0%, 100% {{ opacity: 0.6; }}
    50% {{ opacity: 1; }}
  }}
  .header::before {{ animation: pulse-glow 3s ease-in-out infinite; }}

  /* ── Scrollbar ── */
  ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
  ::-webkit-scrollbar-thumb {{
    background: var(--border-dim); border-radius: 4px;
  }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--cyan-dim); }}
</style>
</head>
<body>

<div id="root"></div>

<script>
  window.__REPORT_DATA__ = {data_json};
  window.__PRICING_DATA__ = {pricing_json};
  window.__REPORT_META__ = {{
    title: {json.dumps(title)},
    timeDesc: {json.dumps(time_desc)},
    region: {json.dumps(region)},
    withPricing: {'true' if with_pricing else 'false'}
  }};
</script>

<script type="text/babel">
const {{ useState, useMemo }} = React;

function formatNumber(n) {{
  if (n == null) return '';
  return n.toLocaleString();
}}

function formatCost(n) {{
  if (n == null) return '';
  if (n === 0) return '$0';
  return '$' + n.toFixed(4);
}}

function SortIcon({{ active, dir }}) {{
  if (!active) return <span className="sort-icon">&#8597;</span>;
  return <span className="sort-icon active">{{dir === 'asc' ? '\\u25B2' : '\\u25BC'}}</span>;
}}

function PricingSection() {{
  const pricing = window.__PRICING_DATA__;
  const [open, setOpen] = useState(false);

  const models = Object.keys(pricing).sort();
  if (models.length === 0) return null;

  function fmtPrice(v) {{
    if (v == null) return '';
    if (v === 0) return '$0';
    if (v < 0.0001) return '$' + v.toExponential(2);
    return '$' + v.toFixed(6).replace(/0+$/, '').replace(/\\.$/, '');
  }}

  return (
    <div className="pricing-section">
      <button className="pricing-toggle" onClick={{() => setOpen(o => !o)}}>
        <span className={{'chevron' + (open ? ' open' : '')}}>&#9654;</span>
        Bedrock Model Pricing Reference
        <span className="pricing-unit">(USD per 1K tokens)</span>
      </button>
      {{open && (
        <div className="pricing-body">
          <table>
            <thead>
              <tr>
                <th>Model ID</th>
                <th className="num">Input</th>
                <th className="num">Output</th>
                <th className="num">Cache Read</th>
                <th className="num">Cache Write</th>
              </tr>
            </thead>
            <tbody>
              {{models.map(m => {{
                const p = pricing[m];
                if (!p) return (
                  <tr key={{m}}>
                    <td>{{m}}</td>
                    <td colSpan={{4}} className="pricing-na">Pricing unavailable</td>
                  </tr>
                );
                return (
                  <tr key={{m}}>
                    <td>{{m}}</td>
                    <td className="num">{{fmtPrice(p.input)}}</td>
                    <td className="num">{{fmtPrice(p.output)}}</td>
                    <td className="num">{{fmtPrice(p.cache_read)}}</td>
                    <td className="num">{{fmtPrice(p.cache_write)}}</td>
                  </tr>
                );
              }})}}
            </tbody>
          </table>
        </div>
      )}}
    </div>
  );
}}

function App() {{
  const data = window.__REPORT_DATA__;
  const meta = window.__REPORT_META__;
  const [filter, setFilter] = useState('');
  const [userFilter, setUserFilter] = useState('__all__');
  const [sortCol, setSortCol] = useState(null);
  const [sortDir, setSortDir] = useState('asc');

  const users = useMemo(() => {{
    const s = new Set(data.map(r => r.IAM_User));
    return ['__all__', ...Array.from(s).sort()];
  }}, [data]);

  const filtered = useMemo(() => {{
    let rows = data;
    if (userFilter !== '__all__') {{
      rows = rows.filter(r => r.IAM_User === userFilter);
    }}
    if (filter) {{
      const lf = filter.toLowerCase();
      rows = rows.filter(r =>
        Object.values(r).some(v =>
          v != null && String(v).toLowerCase().includes(lf)
        )
      );
    }}
    if (sortCol) {{
      rows = [...rows].sort((a, b) => {{
        let va = a[sortCol], vb = b[sortCol];
        if (va == null) va = '';
        if (vb == null) vb = '';
        if (typeof va === 'number' && typeof vb === 'number')
          return sortDir === 'asc' ? va - vb : vb - va;
        return sortDir === 'asc'
          ? String(va).localeCompare(String(vb))
          : String(vb).localeCompare(String(va));
      }});
    }}
    return rows;
  }}, [data, filter, userFilter, sortCol, sortDir]);

  const handleSort = (col) => {{
    if (sortCol === col) {{
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    }} else {{
      setSortCol(col);
      setSortDir('asc');
    }}
  }};

  const baseCols = [
    {{ key: 'IAM_User', label: 'IAM User' }},
    {{ key: 'API_Key_IDs', label: 'API Key IDs' }},
    {{ key: 'App_Profile', label: 'App Profile' }},
    {{ key: 'Model_ID', label: 'Model ID' }},
    {{ key: 'Request_count', label: 'Requests', numeric: true }},
    {{ key: 'Input_Tokens', label: 'Input Tokens', numeric: true }},
    {{ key: 'Output_Tokens', label: 'Output Tokens', numeric: true }},
    {{ key: 'CacheRead_Tokens', label: 'Cache Read', numeric: true }},
    {{ key: 'CacheWrite_Tokens', label: 'Cache Write', numeric: true }},
    {{ key: 'Total_Tokens', label: 'Total Tokens', numeric: true }},
  ];
  const costCols = meta.withPricing ? [
    {{ key: 'Input_Cost_USD', label: 'Input Cost', cost: true }},
    {{ key: 'Output_Cost_USD', label: 'Output Cost', cost: true }},
    {{ key: 'CacheRead_Cost_USD', label: 'CRead Cost', cost: true }},
    {{ key: 'CacheWrite_Cost_USD', label: 'CWrite Cost', cost: true }},
    {{ key: 'Total_Cost_USD', label: 'Total Cost', cost: true }},
  ] : [];
  const columns = [...baseCols, ...costCols];

  /* Build rows with subtotals inserted */
  const displayRows = useMemo(() => {{
    if (!filtered.length) return [];
    const result = [];
    let prevUser = null;
    const accum = {{}};

    const flushSubtotal = (user) => {{
      if (!accum[user]) return;
      result.push({{ _type: 'subtotal', _user: user, ...accum[user] }});
    }};

    for (const row of filtered) {{
      if (prevUser !== null && row.IAM_User !== prevUser) {{
        flushSubtotal(prevUser);
      }}
      prevUser = row.IAM_User;
      if (!accum[row.IAM_User]) {{
        accum[row.IAM_User] = {{}};
        for (const c of columns) {{
          if (c.numeric || c.cost) accum[row.IAM_User][c.key] = 0;
        }}
      }}
      for (const c of columns) {{
        if ((c.numeric || c.cost) && row[c.key] != null) {{
          accum[row.IAM_User][c.key] += row[c.key];
        }}
      }}
      result.push({{ _type: 'row', ...row }});
    }}
    if (prevUser !== null) flushSubtotal(prevUser);
    return result;
  }}, [filtered, columns]);

  /* Grand totals */
  const grand = useMemo(() => {{
    const t = {{}};
    for (const c of columns) {{
      if (c.numeric || c.cost) t[c.key] = 0;
    }}
    for (const row of filtered) {{
      for (const c of columns) {{
        if ((c.numeric || c.cost) && row[c.key] != null) t[c.key] += row[c.key];
      }}
    }}
    return t;
  }}, [filtered, columns]);

  const grandTotalTokens = grand['Total_Tokens'] || 0;
  const grandTotalCost = meta.withPricing ? (grand['Total_Cost_USD'] || 0) : null;

  return (
    <div>
      <div className="header">
        <h1>{{meta.title}} per IAM User</h1>
        <div className="meta">
          <span>&#9670; {{meta.timeDesc}}</span>
          <span className="separator">|</span>
          <span>&#9670; Region: {{meta.region}}</span>
          <span className="separator">|</span>
          <span>&#9670; {{filtered.length}} record{{filtered.length !== 1 ? 's' : ''}}</span>
        </div>
      </div>

      <div className="summary-cards">
        <div className="card">
          <div className="label">Users</div>
          <div className="value">{{new Set(filtered.map(r => r.IAM_User)).size}}</div>
        </div>
        <div className="card">
          <div className="label">Total Tokens</div>
          <div className="value">{{formatNumber(grandTotalTokens)}}</div>
        </div>
        {{grandTotalCost !== null && (
          <div className="card">
            <div className="label">Total Cost</div>
            <div className="value cost-val">{{formatCost(grandTotalCost)}}</div>
          </div>
        )}}
        <div className="card">
          <div className="label">Models</div>
          <div className="value">{{new Set(filtered.map(r => r.Model_ID)).size}}</div>
        </div>
      </div>

      <div className="controls">
        <input
          type="text"
          placeholder="Search across all columns..."
          value={{filter}}
          onChange={{e => setFilter(e.target.value)}}
        />
        <select value={{userFilter}} onChange={{e => setUserFilter(e.target.value)}}>
          {{users.map(u => (
            <option key={{u}} value={{u}}>
              {{u === '__all__' ? 'All Users' : u}}
            </option>
          ))}}
        </select>
      </div>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              {{columns.map(c => (
                <th key={{c.key}} onClick={{() => handleSort(c.key)}}
                    className={{c.numeric ? 'num' : c.cost ? 'cost' : ''}}>
                  {{c.label}}
                  <SortIcon active={{sortCol === c.key}} dir={{sortDir}} />
                </th>
              ))}}
            </tr>
          </thead>
          <tbody>
            {{displayRows.map((row, i) => {{
              if (row._type === 'subtotal') {{
                return (
                  <tr key={{'sub-' + i}} className="subtotal">
                    <td colSpan={{4}}>Subtotal — {{row._user}}</td>
                    {{columns.slice(4).map(c => (
                      <td key={{c.key}} className={{c.cost ? 'cost' : 'num'}}>
                        {{c.cost ? formatCost(row[c.key]) : formatNumber(row[c.key])}}
                      </td>
                    ))}}
                  </tr>
                );
              }}
              return (
                <tr key={{i}}>
                  {{columns.map(c => (
                    <td key={{c.key}} className={{c.numeric ? 'num' : c.cost ? 'cost' : ''}}>
                      {{c.cost ? formatCost(row[c.key])
                        : c.numeric ? formatNumber(row[c.key])
                        : (row[c.key] || '')}}
                    </td>
                  ))}}
                </tr>
              );
            }})}}
          </tbody>
          {{filtered.length > 0 && (
            <tfoot>
              <tr>
                <td colSpan={{4}}>Grand Total</td>
                {{columns.slice(4).map(c => (
                  <td key={{c.key}} className={{c.cost ? 'cost' : 'num'}}>
                    {{c.cost ? formatCost(grand[c.key]) : formatNumber(grand[c.key])}}
                  </td>
                ))}}
              </tr>
            </tfoot>
          )}}
        </table>
      </div>

      <PricingSection />
    </div>
  );
}}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"HTML report written to: {output_path}")


def print_report(rows: list[dict], time_desc: str, region: str,
                 with_pricing: bool):
    """Print formatted table to stdout with per-user subtotals and grand
    total."""
    if not rows:
        print("No token usage data found.")
        return

    title = ("Bedrock Token Consumption & Cost" if with_pricing
             else "Bedrock Token Consumption")
    print(f"\n{title} per IAM User - {time_desc} (region: {region})\n")

    w_user = 45
    w_keys = 30
    w_prof = 45
    w_mid = 50
    w_req = 10
    w_num = 14
    w_cost = 14

    hdr = (
        f"{'IAM User':<{w_user}} "
        f"{'API Key IDs':<{w_keys}} "
        f"{'App Profile':<{w_prof}} "
        f"{'Model ID':<{w_mid}} "
        f"{'Requests':>{w_req}} "
        f"{'Input':>{w_num}} {'Output':>{w_num}} "
        f"{'CacheRead':>{w_num}} {'CacheWrite':>{w_num}} {'Total':>{w_num}}"
    )
    if with_pricing:
        hdr += (
            f" {'Input$':>{w_cost}} {'Output$':>{w_cost}} "
            f"{'CRead$':>{w_cost}} {'CWrite$':>{w_cost}} {'Total$':>{w_cost}}"
        )

    sep = "-" * len(hdr)
    print("=" * len(hdr))
    print(title.upper())
    print(f"Time Range: {time_desc} | Region: {region}")
    print("=" * len(hdr))
    print()
    print(hdr)
    print(sep)

    prev_user = None
    user_totals: dict[str, dict] = {}

    def _init_totals():
        return {
            "input": 0, "output": 0, "cache_read": 0, "cache_write": 0,
            "total": 0, "input_cost": 0.0, "output_cost": 0.0,
            "cache_read_cost": 0.0, "cache_write_cost": 0.0, "total_cost": 0.0,
        }

    def _print_subtotal(user):
        ut = user_totals[user]
        sub_line = (
            f"  {'[Subtotal]':<{w_user - 2}} "
            f"{'':<{w_keys}} {'':<{w_prof}} {'':<{w_mid}} "
            f"{'':{w_req}} "
            f"{ut['input']:>{w_num},} {ut['output']:>{w_num},} "
            f"{ut['cache_read']:>{w_num},} {ut['cache_write']:>{w_num},} "
            f"{ut['total']:>{w_num},}"
        )
        if with_pricing:
            sub_line += (
                f" {ut['input_cost']:>{w_cost}.4f} "
                f"{ut['output_cost']:>{w_cost}.4f} "
                f"{ut['cache_read_cost']:>{w_cost}.4f} "
                f"{ut['cache_write_cost']:>{w_cost}.4f} "
                f"{ut['total_cost']:>{w_cost}.4f}"
            )
        print(sub_line)
        print(sep)

    for row in rows:
        user = row["IAM_User"]
        if user != prev_user and prev_user is not None:
            _print_subtotal(prev_user)
        prev_user = user

        if user not in user_totals:
            user_totals[user] = _init_totals()
        ut = user_totals[user]
        ut["input"] += row["Input_Tokens"]
        ut["output"] += row["Output_Tokens"]
        ut["cache_read"] += row["CacheRead_Tokens"]
        ut["cache_write"] += row["CacheWrite_Tokens"]
        ut["total"] += row["Total_Tokens"]
        if with_pricing and row.get("Total_Cost_USD") is not None:
            ut["input_cost"] += row.get("Input_Cost_USD", 0) or 0
            ut["output_cost"] += row.get("Output_Cost_USD", 0) or 0
            ut["cache_read_cost"] += row.get("CacheRead_Cost_USD", 0) or 0
            ut["cache_write_cost"] += row.get("CacheWrite_Cost_USD", 0) or 0
            ut["total_cost"] += row.get("Total_Cost_USD", 0) or 0

        disp_user = (user[:w_user - 2] + ".."
                     if len(user) > w_user else user)
        disp_keys = (row["API_Key_IDs"][:w_keys - 2] + ".."
                     if len(row["API_Key_IDs"]) > w_keys
                     else row["API_Key_IDs"])
        disp_prof = (row["App_Profile"][:w_prof - 2] + ".."
                     if len(row["App_Profile"]) > w_prof
                     else row["App_Profile"])
        disp_mid = (row["Model_ID"][:w_mid - 2] + ".."
                    if len(row["Model_ID"]) > w_mid else row["Model_ID"])

        rc = row.get("Request_count")
        req_str = f"{rc:,}" if rc else ""

        line = (
            f"{disp_user:<{w_user}} "
            f"{disp_keys:<{w_keys}} "
            f"{disp_prof:<{w_prof}} "
            f"{disp_mid:<{w_mid}} "
            f"{req_str:>{w_req}} "
            f"{row['Input_Tokens']:>{w_num},} {row['Output_Tokens']:>{w_num},} "
            f"{row['CacheRead_Tokens']:>{w_num},} "
            f"{row['CacheWrite_Tokens']:>{w_num},} "
            f"{row['Total_Tokens']:>{w_num},}"
        )
        if with_pricing:
            if row.get("Total_Cost_USD") is not None:
                line += (
                    f" {row['Input_Cost_USD']:>{w_cost}.4f} "
                    f"{row['Output_Cost_USD']:>{w_cost}.4f} "
                    f"{row['CacheRead_Cost_USD']:>{w_cost}.4f} "
                    f"{row['CacheWrite_Cost_USD']:>{w_cost}.4f} "
                    f"{row['Total_Cost_USD']:>{w_cost}.4f}"
                )
            else:
                line += (f" {'':{w_cost}} {'':{w_cost}} {'':{w_cost}} "
                         f"{'':{w_cost}} {'':{w_cost}}")
        print(line)

    # Last user subtotal
    if prev_user is not None:
        _print_subtotal(prev_user)

    # Grand total
    grand = {
        "input": sum(r["Input_Tokens"] for r in rows),
        "output": sum(r["Output_Tokens"] for r in rows),
        "cache_read": sum(r["CacheRead_Tokens"] for r in rows),
        "cache_write": sum(r["CacheWrite_Tokens"] for r in rows),
        "total": sum(r["Total_Tokens"] for r in rows),
    }
    grand_line = (
        f"{'GRAND TOTAL':<{w_user}} "
        f"{'':<{w_keys}} {'':<{w_prof}} {'':<{w_mid}} "
        f"{'':{w_req}} "
        f"{grand['input']:>{w_num},} {grand['output']:>{w_num},} "
        f"{grand['cache_read']:>{w_num},} {grand['cache_write']:>{w_num},} "
        f"{grand['total']:>{w_num},}"
    )
    if with_pricing:
        gc = {
            "input_cost": sum(r.get("Input_Cost_USD", 0) or 0 for r in rows),
            "output_cost": sum(r.get("Output_Cost_USD", 0) or 0
                               for r in rows),
            "cache_read_cost": sum(r.get("CacheRead_Cost_USD", 0) or 0
                                   for r in rows),
            "cache_write_cost": sum(r.get("CacheWrite_Cost_USD", 0) or 0
                                    for r in rows),
            "total_cost": sum(r.get("Total_Cost_USD", 0) or 0 for r in rows),
        }
        grand_line += (
            f" {gc['input_cost']:>{w_cost}.4f} "
            f"{gc['output_cost']:>{w_cost}.4f} "
            f"{gc['cache_read_cost']:>{w_cost}.4f} "
            f"{gc['cache_write_cost']:>{w_cost}.4f} "
            f"{gc['total_cost']:>{w_cost}.4f}"
        )
    print(grand_line)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()
    region = args.region or os.environ.get("AWS_REGION", "us-east-1")
    with_pricing = args.with_pricing == "true"
    bedrock_apikey_only = args.bedrock_apikey_only == "yes"

    start, end, time_desc = resolve_time_range(args)

    bedrock = boto3.client("bedrock", region_name=region)
    iam = boto3.client("iam", region_name=region)

    # Step 1: Detect logging config and let user choose source
    print("Detecting Bedrock model invocation logging configuration...")
    log_config = detect_logging_config(bedrock, args)

    s3_bucket = log_config["s3_bucket"]
    s3_prefix = log_config["s3_prefix"] or ""
    log_group = log_config["log_group"]

    print("\nSelected log sources:")
    if s3_bucket:
        print(f"  S3: s3://{s3_bucket}/{s3_prefix}")
    if log_group:
        print(f"  CloudWatch: {log_group}")
    print()

    # Step 2: Verify IAM permissions before proceeding
    if not verify_permissions(region, args.query_engine, with_pricing,
                              s3_bucket, log_group):
        sys.exit(1)

    # Build lookups
    print("Loading API key mappings from IAM...")
    api_key_map = get_api_key_map(iam)
    print(f"  {len(api_key_map)} users with API keys found")

    print("Loading Bedrock inference profiles...")
    profile_count = len(build_profile_lookup(bedrock, region))
    print(f"  {profile_count} profiles/models loaded\n")

    # Run engines
    s3_usage = None
    cw_usage = None

    start_date_str = start.strftime("%Y-%m-%d")
    end_date_str = end.strftime("%Y-%m-%d")

    if s3_bucket:
        if args.query_engine == "athena":
            athena_client = boto3.client("athena", region_name=region)
            athena_output = (args.athena_output
                             or f"s3://{s3_bucket}/{ATHENA_OUTPUT_PREFIX}")
            s3_usage = run_athena_engine(
                athena_client, s3_bucket, s3_prefix,
                start_date_str, end_date_str, athena_output)
        else:
            s3_client = boto3.client("s3", region_name=region)
            s3_usage = run_s3_engine(
                s3_client, s3_bucket, s3_prefix,
                start_date_str, end_date_str, args.workers)

    if log_group:
        logs_client = boto3.client("logs", region_name=region)
        cw_usage = run_cloudwatch_engine(logs_client, log_group, start, end)

    # Merge
    usage = merge_usage(s3_usage, cw_usage)

    if not usage:
        print("No token usage data found.")
        return

    # Build enriched rows
    rows = build_enriched_rows(
        usage, api_key_map, bedrock,
        region, bedrock_apikey_only, with_pricing)

    if not rows:
        filter_msg = (" matching 'BedrockAPIKey-*'"
                      if bedrock_apikey_only else "")
        print(f"No IAM users{filter_msg} found in the query results.")
        if bedrock_apikey_only:
            print("Hint: use --bedrock-apikey-only=no to include all "
                  "IAM users.")
        return

    # Output
    print_report(rows, time_desc, region, with_pricing)

    if args.output:
        # Resolve output path: if --output is just a filename, place it
        # inside --output-dir; if it's an absolute or relative path with
        # directories, use it as-is.
        output_file = args.output
        if os.path.dirname(output_file) == "":
            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = str(output_dir / output_file)

        ext = os.path.splitext(output_file)[1].lower()
        if ext == ".csv":
            write_csv(rows, output_file, with_pricing)
        elif ext == ".html":
            write_html(rows, output_file, time_desc, region, with_pricing)
        else:
            write_txt(rows, output_file, time_desc, region, with_pricing)


if __name__ == "__main__":
    main()
