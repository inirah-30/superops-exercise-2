import json
import os
import secrets
import string
import urllib.parse

import boto3
import yaml

CONFIG_FILE = "config/users.yaml"
CREDENTIALS_DIR = "generated_credentials"
IAM_USER_CHANGE_PASSWORD_POLICY = "arn:aws:iam::aws:policy/IAMUserChangePassword"

iam = boto3.client("iam")


def generate_temp_password(length=16):
    """Generate a temporary console password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def load_config():
    """Load users from YAML configuration."""
    with open(CONFIG_FILE, "r") as file:
        return yaml.safe_load(file)


def check_user_exists(username):
    """Check whether an IAM user exists."""
    try:
        iam.get_user(UserName=username)
        return True
    except iam.exceptions.NoSuchEntityException:
        return False


def create_user(username, tags=None):
    """Create an IAM user if it does not already exist. User creation is idempotent."""
    if check_user_exists(username):
        print(f"[{username}] User already exists")
        return

    tag_list = [{"Key": key, "Value": str(value)} for key, value in (tags or {}).items()]

    iam.create_user(UserName=username, Tags=tag_list)
    print(f"[{username}] User created")


def add_user_to_groups(username, groups):
    """Add the user to all requested IAM groups. Groups must already exist."""
    for group_name in groups:
        try:
            iam.get_group(GroupName=group_name)
        except iam.exceptions.NoSuchEntityException:
            print(f"[{username}] ERROR: Group '{group_name}' does not exist")
            continue

        iam.add_user_to_group(GroupName=group_name, UserName=username)
        print(f"[{username}] Added to group: {group_name}")


def load_policy_file(policy_file):
    """Load a JSON policy from a local file."""
    with open(policy_file, "r") as file:
        return json.load(file)


def normalize_statements(statements):
    """IAM allows Statement to be either a single object or a list. Normalize it to a list."""
    if isinstance(statements, dict):
        return [statements]
    return statements or []


def get_existing_inline_policy(username, policy_name):
    """
    Retrieve the existing inline policy.

    boto3 may return PolicyDocument as a dictionary or as an encoded string, so handle both.
    """
    try:
        response = iam.get_user_policy(UserName=username, PolicyName=policy_name)
        policy_document = response["PolicyDocument"]

        if isinstance(policy_document, dict):
            return policy_document

        return json.loads(urllib.parse.unquote(policy_document))
    except iam.exceptions.NoSuchEntityException:
        return None


def merge_policy(existing_policy, new_policy):
    """
    Merge policy statements using Sid.

    Behaviour:
    - Existing Sid + new Sid -> update existing statement
    - New Sid -> add statement
    - Existing Sid not present in new policy -> keep existing statement

    Therefore permissions are not accidentally removed.
    """
    if existing_policy is None:
        return new_policy

    existing_statements = normalize_statements(existing_policy.get("Statement", []))
    new_statements = normalize_statements(new_policy.get("Statement", []))

    statements_without_sid = [statement for statement in existing_statements if not statement.get("Sid")]

    statement_map = {statement["Sid"]: statement for statement in existing_statements if statement.get("Sid")}

    for statement in new_statements:
        sid = statement.get("Sid")
        if sid:
            statement_map[sid] = statement
        else:
            statements_without_sid.append(statement)

    merged_statements = list(statement_map.values()) + statements_without_sid

    return {
        "Version": new_policy.get("Version", existing_policy.get("Version", "2012-10-17")),
        "Statement": merged_statements
    }


def attach_or_update_policy(username, policy_file):
    """Attach or update the user's inline policy. Multiple policy files are merged into one inline policy."""
    policy_name = f"{username}-inline-policy"
    new_policy = load_policy_file(policy_file)
    existing_policy = get_existing_inline_policy(username, policy_name)
    merged_policy = merge_policy(existing_policy, new_policy)

    iam.put_user_policy(UserName=username, PolicyName=policy_name, PolicyDocument=json.dumps(merged_policy))

    if existing_policy:
        print(f"[{username}] Inline policy updated from {policy_file}")
    else:
        print(f"[{username}] Inline policy created from {policy_file}")


def enable_console_access(username, credentials):
    """
    Create an IAM console login profile.

    A temporary password is generated and the user is forced to change it during first login.
    IAMUserChangePassword is also attached so the user can manage their own password.
    """
    try:
        password = generate_temp_password()
        iam.create_login_profile(UserName=username, Password=password, PasswordResetRequired=True)
        iam.attach_user_policy(UserName=username, PolicyArn=IAM_USER_CHANGE_PASSWORD_POLICY)
        credentials.append((username, f"Console Password: {password}\nPassword Reset Required: Yes"))
        print(f"[{username}] Console access enabled")
    except iam.exceptions.EntityAlreadyExistsException:
        print(f"[{username}] Console access already exists")


def enable_cli_access(username, credentials):
    """Create an access key for programmatic / CLI access. If the user already has an access key, no new key is created."""
    existing_keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

    if existing_keys:
        print(f"[{username}] Access key already exists, skipping")
        return

    response = iam.create_access_key(UserName=username)
    access_key = response["AccessKey"]

    credentials.append((username, f"Access Key ID: {access_key['AccessKeyId']}\nSecret Access Key: {access_key['SecretAccessKey']}"))
    print(f"[{username}] CLI access enabled")


def deactivate_user(username):
    """
    Disable access for an inactive user. The IAM user is NOT deleted.

    Access keys are disabled and console login is removed.
    """
    if not check_user_exists(username):
        print(f"[{username}] User does not exist")
        return

    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
    for key in keys:
        if key["Status"] == "Active":
            iam.update_access_key(UserName=username, AccessKeyId=key["AccessKeyId"], Status="Inactive")
            print(f"[{username}] Access key disabled: {key['AccessKeyId']}")

    try:
        iam.delete_login_profile(UserName=username)
        print(f"[{username}] Console access disabled")
    except iam.exceptions.NoSuchEntityException:
        print(f"[{username}] Console access already disabled")


def validate_access(username, user_config):
    """Verify that the actual AWS state matches the requested configuration."""
    checks = {}
    passed = True

    checks["user_exists"] = check_user_exists(username)

    if not checks["user_exists"]:
        return {"username": username, "passed": False, "checks": checks}

    if user_config.get("status") == "inactive":
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        active_keys = [key for key in keys if key["Status"] == "Active"]
        checks["no_active_access_keys"] = (len(active_keys) == 0)

        if not checks["no_active_access_keys"]:
            passed = False

        try:
            iam.get_login_profile(UserName=username)
            checks["console_access_disabled"] = False
            passed = False
        except iam.exceptions.NoSuchEntityException:
            checks["console_access_disabled"] = True

        return {"username": username, "passed": passed, "checks": checks}

    requested_groups = user_config.get("groups", [])
    actual_groups = [group["GroupName"] for group in iam.list_groups_for_user(UserName=username)["Groups"]]

    for group_name in requested_groups:
        check_name = f"group_{group_name}"
        checks[check_name] = (group_name in actual_groups)
        if not checks[check_name]:
            passed = False

    requested_policies = user_config.get("policies", [])
    policy_name = f"{username}-inline-policy"

    if requested_policies:
        existing_policy = get_existing_inline_policy(username, policy_name)
        checks["inline_policy"] = (existing_policy is not None)
        if not checks["inline_policy"]:
            passed = False

    if user_config.get("console_access", False):
        try:
            iam.get_login_profile(UserName=username)
            checks["console_access"] = True
        except iam.exceptions.NoSuchEntityException:
            checks["console_access"] = False
            passed = False

    if user_config.get("cli_access", False):
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
        checks["cli_access"] = (len(keys) > 0)
        if not checks["cli_access"]:
            passed = False

    return {"username": username, "passed": passed, "checks": checks}


def save_credentials(credentials):
    """
    Save generated credentials separately for each user.

    In production, use AWS Secrets Manager or another secure credential delivery mechanism.
    """
    if not credentials:
        return

    os.makedirs(CREDENTIALS_DIR, exist_ok=True)

    user_credentials = {}

    for username, data in credentials:
        user_credentials.setdefault(username, [])
        user_credentials[username].append(data)

    for username, data_list in user_credentials.items():
        path = os.path.join(CREDENTIALS_DIR, f"{username}.txt")

        with open(path, "w") as file:
            file.write(f"Credentials for {username}\n")
            file.write("=" * 40 + "\n")
            for data in data_list:
                file.write(data)
                file.write("\n\n")

        os.chmod(path, 0o600)
        print(f"[{username}] Credentials saved to {path}")


def provision_user(user_config, credentials):
    """Provision one user based on the YAML configuration."""
    username = user_config["username"]

    print(f"\n{'=' * 50}")
    print(f"Processing: {username}")
    print(f"Status: {user_config.get('status', 'active')}")
    print(f"{'=' * 50}")

    if user_config.get("status") == "inactive":
        deactivate_user(username)
        result = validate_access(username, user_config)
        status = "PASSED" if result["passed"] else "FAILED"
        print(f"[{username}] Validation: {status}")
        print(f"[{username}] Checks: {result['checks']}")
        return result

    create_user(username, tags=user_config.get("tags", {}))

    groups = user_config.get("groups", [])
    if groups:
        add_user_to_groups(username, groups)

    policies = user_config.get("policies", [])
    for policy_file in policies:
        attach_or_update_policy(username, policy_file)

    if user_config.get("console_access", False):
        enable_console_access(username, credentials)

    if user_config.get("cli_access", False):
        enable_cli_access(username, credentials)

    result = validate_access(username, user_config)
    status = "PASSED" if result["passed"] else "FAILED"
    print(f"[{username}] Validation: {status}")
    print(f"[{username}] Checks: {result['checks']}")

    return result


def main():
    """Main provisioning workflow."""
    config = load_config()
    credentials = []
    validation_results = []
    users = config.get("users", [])

    for user_config in users:
        try:
            result = provision_user(user_config, credentials)
            validation_results.append(result)
        except Exception as error:
            username = user_config.get("username", "unknown")
            print(f"[{username}] ERROR: {error}")
            validation_results.append({"username": username, "passed": False, "checks": {}})

    save_credentials(credentials)

    failed = [result for result in validation_results if not result["passed"]]
    successful = len(validation_results) - len(failed)

    print(f"\n{'=' * 50}")
    print("PROVISIONING COMPLETE")
    print(f"{'=' * 50}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(failed)}")

    if failed:
        print(f"Failed users: {[result['username'] for result in failed]}")


if __name__ == "__main__":
    main()