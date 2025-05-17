import boto3
import json
import os

# Constants
BASE_DIR = "iam"
INLINE_DIR = os.path.join(BASE_DIR, "policies", "inline")
AWS_MANAGED_DIR = os.path.join(BASE_DIR, "policies", "aws-managed")
USERS_DIR = os.path.join(BASE_DIR, "users")
GROUPS_DIR = os.path.join(BASE_DIR, "groups")
ROLES_DIR = os.path.join(BASE_DIR, "roles")

iam = boto3.client('iam')


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)


def sync_user(user_name):
    print(f"[USER] {user_name}")

    # User metadata
    user = iam.get_user(UserName=user_name)['User']
    write_json(os.path.join(USERS_DIR, f"{user_name}.json"), user)

    # Inline Policies
    inline_policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
    for policy_name in inline_policies:
        policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
        write_json(os.path.join(INLINE_DIR, f"{policy_name}.json"), policy['PolicyDocument'])

    # Attached Managed Policies
    attached = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    for policy in attached:
        fetch_and_save_managed_policy(policy['PolicyArn'], policy['PolicyName'])


def sync_group(group_name):
    print(f"[GROUP] {group_name}")

    # Group metadata
    group = iam.get_group(GroupName=group_name)['Group']
    write_json(os.path.join(GROUPS_DIR, f"{group_name}.json"), group)

    # Inline Policies
    inline_policies = iam.list_group_policies(GroupName=group_name)['PolicyNames']
    for policy_name in inline_policies:
        policy = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
        write_json(os.path.join(INLINE_DIR, f"{group_name}-{policy_name}.json"), policy['PolicyDocument'])

    # Attached Managed Policies
    attached = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
    for policy in attached:
        fetch_and_save_managed_policy(policy['PolicyArn'], policy['PolicyName'])


def sync_role(role_name):
    print(f"[ROLE] {role_name}")

    # Role metadata and trust policy
    role = iam.get_role(RoleName=role_name)['Role']
    write_json(os.path.join(ROLES_DIR, f"{role_name}.json"), role)

    # Inline Policies
    inline_policies = iam.list_role_policies(RoleName=role_name)['PolicyNames']
    for policy_name in inline_policies:
        policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        write_json(os.path.join(INLINE_DIR, f"{role_name}-{policy_name}.json"), policy['PolicyDocument'])

    # Attached Managed Policies
    attached = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    for policy in attached:
        fetch_and_save_managed_policy(policy['PolicyArn'], policy['PolicyName'])


def fetch_and_save_managed_policy(policy_arn, policy_name):
    path = os.path.join(AWS_MANAGED_DIR, f"{policy_name}.json")
    if not os.path.exists(path):
        print(f"  Saving managed policy: {policy_name}")
        policy_meta = iam.get_policy(PolicyArn=policy_arn)['Policy']
        version = policy_meta['DefaultVersionId']
        doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']['Document']
        write_json(path, doc)


def main():
    print("Starting IAM Sync...")

    # Get all users in the Administrators group
    admin_group_name = "Administrators"
    try:
        admin_users = iam.get_group(GroupName=admin_group_name)['Users']
        admin_usernames = set(u['UserName'] for u in admin_users)
        print(f"Skipping {len(admin_usernames)} admin users")
    except iam.exceptions.NoSuchEntityException:
        print(f"Group '{admin_group_name}' not found — continuing without admin exclusion.")
        admin_usernames = set()

    # USERS
    for user in iam.list_users()['Users']:
        username = user['UserName']
        if username in admin_usernames:
            print(f"Skipping admin user: {username}")
            continue
        sync_user(username)

    # GROUPS (optional – still include)
    for group in iam.list_groups()['Groups']:
        sync_group(group['GroupName'])

    # ROLES
    for role in iam.list_roles()['Roles']:
        sync_role(role['RoleName'])

    print("IAM Sync Complete")



if __name__ == "__main__":
    main()
