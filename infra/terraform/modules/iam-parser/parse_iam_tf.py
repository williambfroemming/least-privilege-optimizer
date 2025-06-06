#!/usr/bin/env python3
import hcl2
import os
import json
import sys
import boto3
from datetime import datetime

def collect_iam_resources(tf_folder, account_id):
    iam_resource_types = {
        "aws_iam_user": "user",
        "aws_iam_role": "role",
        "aws_iam_group": "group",
        "aws_iam_policy": "policy",
        "aws_iam_role_policy_attachment": "role-policy-attachment",
        "aws_iam_user_policy_attachment": "user-policy-attachment",
        "aws_iam_group_policy_attachment": "group-policy-attachment"
    }

    result = {rtype: [] for rtype in iam_resource_types}

    for root, _, files in os.walk(tf_folder):
        for file in files:
            if file.endswith(".tf"):
                with open(os.path.join(root, file), 'r') as f:
                    try:
                        data = hcl2.load(f)
                        resources = data.get("resource", [])

                        # Handle both dict and list-of-dicts
                        if isinstance(resources, dict):
                            resources = [resources]

                        for block in resources:
                            for res_type, res_defs in block.items():
                                if res_type in iam_resource_types:
                                    for tf_resource_name, resource_body in res_defs.items():
                                        name = resource_body.get("name", tf_resource_name)

                                        entry = {
                                            "tf_resource_name": tf_resource_name,
                                            "name": name,
                                            "type": iam_resource_types[res_type]
                                        }

                                        if res_type in ["aws_iam_user", "aws_iam_role", "aws_iam_group"]:
                                            entry["arn"] = f"arn:aws:iam::{account_id}:{entry['type']}/{name}"

                                        result[res_type].append(entry)
                    except Exception as e:
                        continue

    return result

if __name__ == "__main__":
    tf_path = sys.argv[1]
    s3_bucket = os.environ.get("S3_BUCKET_NAME")
    s3_prefix = os.environ.get("S3_KEY_PREFIX", "iam-parsed")

    if not s3_bucket:
        print("Missing required env var: S3_BUCKET_NAME", file=sys.stderr)
        sys.exit(1)

    # Get AWS Account ID for ARN generation
    account_id = boto3.client("sts").get_caller_identity()["Account"]

    resources = collect_iam_resources(tf_path, account_id)

    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    key_versioned = f"{s3_prefix}/iam_resources_{timestamp}.json"
    key_latest = f"{s3_prefix}/latest.json"

    json_data = json.dumps(resources, indent=2)

    s3 = boto3.client("s3")
    s3.put_object(Bucket=s3_bucket, Key=key_versioned, Body=json_data, ContentType="application/json")
    s3.put_object(Bucket=s3_bucket, Key=key_latest, Body=json_data, ContentType="application/json")

    print(f"Wrote {key_versioned} and {key_latest} to s3://{s3_bucket}/")
