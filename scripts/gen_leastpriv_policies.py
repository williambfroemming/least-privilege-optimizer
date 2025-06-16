import json
import os

FINDINGS_FILE = 'access_analyzer_findings.json'
OUTPUT_DIR = 'generated_policies'

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_policy_block(resource_name, findings):
    """
    Returns a Terraform HCL string for an aws_iam_policy resource.
    """
    statements = []
    for finding in findings:
        actions = finding.get('actions', [])
        resources = finding.get('resources', [])
        if actions and resources:
            statements.append({
                "Effect": "Allow",
                "Action": actions,
                "Resource": resources
            })
    if not statements:
        # If no findings, create an empty deny-all policy or skip
        return None

    policy_block = f'''
resource "aws_iam_policy" "least_privilege_{resource_name}" {{
  name   = "least-privilege-{resource_name}"
  policy = jsonencode({{
    "Version": "2012-10-17",
    "Statement": {json.dumps(statements, indent=4)}
  }})
}}
'''
    return policy_block

def main():
    with open(FINDINGS_FILE, 'r') as f:
        findings_data = json.load(f)

    for resource_name, findings in findings_data.items():
        policy_hcl = generate_policy_block(resource_name, findings)
        if policy_hcl:
            output_path = os.path.join(OUTPUT_DIR, f'least_privilege_{resource_name}.tf')
            with open(output_path, 'w') as out_f:
                out_f.write(policy_hcl)
            print(f"Generated policy for {resource_name}: {output_path}")
        else:
            print(f"No findings for {resource_name}, no policy generated.")

if __name__ == '__main__':
    main()
