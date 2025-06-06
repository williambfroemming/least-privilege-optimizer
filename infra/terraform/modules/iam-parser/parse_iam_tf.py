#!/usr/bin/env python3
import hcl2
import os
import json
import sys
import boto3
from datetime import datetime

def collect_iam_resources(tf_folder):
    iam_resources = {
        "aws_iam_user": [],
        "aws_iam_role": [],
        "aws_iam_group": [],
        "aws_iam_policy": [],
        "aws_iam_role_policy_attachment": [],
        "aws_iam_user_policy_attachment": [],
        "aws_iam_group_policy_attachment": [],
    }

    for root, _, files in os.walk(tf_folder):
        for file in files:
            if file.endswith(".tf"):
                with open(os.path.join(root, file), 'r') as f:
                    try:
                        data = hcl2.load(f)
                        if "resource" in data:
                            for res_type, res_defs in data["resource"].items():
                                if res_type in iam_resources:
                                    for name in res_defs:
                                        iam_resources[res_type].append(name)
                    except Exception:
                        continue

    return iam_resources

if __name__ == "__main__":
    tf_path = sys.argv[1]
    s3_bucket = os.environ.get("S3_BUCKET_NAME")
    s3_prefix = os.environ.get("S3_KEY_PREFIX", "iam-parsed")

    if not s3_bucket:
        print("Missing required env var: S3_BUCKET_NAME", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    key_versioned = f"{s3_prefix}/iam_resources_{timestamp}.json"
    key_latest = f"{s3_prefix}/latest.json"

    resources = collect_iam_resources(tf_path)

    s3 = boto3.client("s3")
    json_data = json.dumps(resources)

    # Upload versioned scan
    s3.put_object(
        Bucket=s3_bucket,
        Key=key_versioned,
        Body=json_data,
        ContentType="application/json"
    )

    # Upload/update latest.json
    s3.put_object(
        Bucket=s3_bucket,
        Key=key_latest,
        Body=json_data,
        ContentType="application/json"
    )

    print(f"Wrote {key_versioned} and {key_latest} to s3://{s3_bucket}/")