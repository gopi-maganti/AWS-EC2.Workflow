import boto3
import paramiko
import time
import logging
import argparse
from botocore.exceptions import ClientError, WaiterError

# -----------------------------
# Logging Configuration
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


# -----------------------------
# Load Public Key from Private Key
# -----------------------------
def _load_public_key_from_private(ssh_private_key_path: str) -> str:
    """
    Build an OpenSSH-formatted public key string from a private key file.
    Supports RSA, ECDSA, ED25519, and DSS.
    Returns: e.g. 'ssh-rsa AAAAB3...'

    Args:
        ssh_private_key_path: Path to the private key file (.pem)

    Raises:
        RuntimeError: If the key cannot be parsed or is of an unsupported type.
    """
    loaders = [
        paramiko.RSAKey.from_private_key_file,
        paramiko.ECDSAKey.from_private_key_file,
        paramiko.Ed25519Key.from_private_key_file,
        paramiko.DSSKey.from_private_key_file,
    ]
    last_err = None
    for loader in loaders:
        try:
            key = loader(ssh_private_key_path)
            return f"{key.get_name()} {key.get_base64()}"
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Unable to parse private key at {ssh_private_key_path}: {last_err}")


# -----------------------------
# Ensure EC2 Key Pair Exists
# -----------------------------
def ensure_key_pair(region: str, key_name: str, *, public_key_path: str | None = None,
                    private_key_path: str | None = None) -> None:
    """
    Ensure an EC2 key pair named `key_name` exists in `region`.
    - If it exists: do nothing.
    - If missing: import using either `public_key_path` (.pub) or derive from `private_key_path` (.pem).

    Args:
        region: AWS region (e.g. 'us-east-1')
        key_name: Name of the EC2 key pair
        public_key_path: Path to the public key file (.pub)
        private_key_path: Path to the private key file (.pem)

    Raises:
        ValueError: If neither or both of public_key_path and private_key_path are provided.
        ClientError: If AWS API calls fail.
    """
    ec2 = boto3.client("ec2", region_name=region)

    # Check if already a key pair exists
    try:
        ec2.describe_key_pairs(KeyNames=[key_name])
        logger.info(f"EC2 key pair '{key_name}' already exists in {region}.")
        return
    except ClientError as e:
        # If it's truly missing, AWS returns InvalidKeyPair.NotFound
        if e.response.get("Error", {}).get("Code") != "InvalidKeyPair.NotFound":
            logger.error(f"Failed describing key pair '{key_name}': {e}")
            raise
        logger.info(f"EC2 key pair '{key_name}' not found; importing...")

    # Obtain public key material
    if public_key_path:
        with open(public_key_path, "r", encoding="utf-8") as f:
            public_key_material = f.read().strip()
    elif private_key_path:
        public_key_material = _load_public_key_from_private(private_key_path)
    else:
        raise ValueError("You must provide either public_key_path or private_key_path to import key pair.")

    # Import the key pair
    try:
        ec2.import_key_pair(
            KeyName=key_name,
            PublicKeyMaterial=public_key_material.encode("utf-8")
        )
        logger.info(f"Imported EC2 key pair '{key_name}' into {region}.")
    except ClientError as e:
        # If there is a race and another job imported it, be tolerant
        if e.response.get("Error", {}).get("Code") == "InvalidKeyPair.Duplicate":
            logger.info(f"Key pair '{key_name}' was created concurrently; continuing.")
            return
        logger.error(f"Failed to import key pair '{key_name}': {e}")
        raise


# -----------------------------
# Check if an EC2 instance exists
# -----------------------------
def instance_exists(instance_id, region):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Checking if instance {instance_id} exists in region {region}...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        exists = len(response["Reservations"]) > 0
        if exists:
            logger.info(f"Instance {instance_id} exists.")
        else:
            logger.info(f"Instance {instance_id} does not exist.")
        return exists
    except ClientError as e:
        logger.error(f"Failed to describe instance {instance_id}: {e}")
        return False


# -----------------------------
# Get or create an EC2 instance
# -----------------------------
def get_or_create_instance(region, ami_id, instance_type, key_name, tag_key="Name", tag_value="fruitstore-ec2"):
    ec2 = boto3.client("ec2", region_name=region)

    # Ensure the key pair exists before any RunInstances call
    # We use the private key file that your action writes as 'fruitstore.pem'
    try:
        ensure_key_pair(region, key_name, private_key_path="fruitstore.pem")
    except Exception:
        logger.error("Could not ensure/import EC2 key pair; aborting instance creation.")
        raise

    try:
        logger.info(f"Checking for existing EC2 instance with tag [{tag_key}: {tag_value}] in region {region}...")
        response = ec2.describe_instances(
            Filters=[
                {"Name": f"tag:{tag_key}", "Values": [tag_value]},
                {"Name": "instance-state-name", "Values": ["pending", "running"]}
            ]
        )
        for reservation in response["Reservations"]:
            for instance in reservation["Instances"]:
                logger.info(f"Reusing existing instance: {instance['InstanceId']}")
                return instance["InstanceId"]
    except ClientError as e:
        logger.error(f"Error while describing instances: {e}")
        raise

    try:
        logger.info("No existing instance found. Creating new EC2 instance...")
        instances = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': tag_key, 'Value': tag_value}]
            }]
        )
        instance_id = instances["Instances"][0]["InstanceId"]
        logger.info(f"Created instance: {instance_id}")

        waiter = ec2.get_waiter("instance_running")
        logger.info("Waiting for instance to enter 'running' state...")
        waiter.wait(InstanceIds=[instance_id])
        logger.info(f"Instance {instance_id} is now running.")
        return instance_id

    except ClientError as e:
        logger.error(f"Failed to create EC2 instance: {e}")
        raise
    except WaiterError as e:
        logger.error(f"Waiter failed while waiting for instance to run: {e}")
        raise
    except Exception as e:
        logger.exception("Unexpected error during instance creation")
        raise



# -----------------------------
# Get public IP of an EC2 instance
# -----------------------------
def get_instance_public_ip(instance_id, region):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Fetching public IP for instance {instance_id}...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if reservations and reservations[0]["Instances"]:
            ip = reservations[0]["Instances"][0].get("PublicIpAddress")
            logger.info(f"Public IP of instance {instance_id}: {ip}")
            return ip
        logger.warning(f"No public IP found for instance {instance_id}.")
        return None
    except ClientError as e:
        logger.error(f"Failed to get public IP for {instance_id}: {e}")
        return None


# -----------------------------
# Run a script over SSH on an EC2 instance
# -----------------------------
def run_script_over_ssh(ip_address, ssh_key_path, script_path, username="ec2-user"):
    logger.info(f"Attempting SSH connection to {ip_address}...")

    try:
        key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connected = False
        for attempt in range(5):
            try:
                client.connect(hostname=ip_address, username=username, pkey=key, timeout=10)
                connected = True
                break
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1}: SSH not ready. Retrying... ({e})")
                time.sleep(5)

        if not connected:
            raise RuntimeError("SSH connection failed after multiple attempts.")

        logger.info("SSH connection established.")

        with open(script_path, "r") as file:
            commands = file.read()

        logger.info(f"Executing script: {script_path}")
        stdin, stdout, stderr = client.exec_command(commands)

        stdout_output = stdout.read().decode()
        stderr_output = stderr.read().decode()

        logger.info("Script STDOUT:\n" + stdout_output)
        if stderr_output.strip():
            logger.warning("Script STDERR:\n" + stderr_output)

        client.close()

    except Exception as e:
        logger.exception(f"Error running SSH command on EC2 {ip_address}")
        raise


# -----------------------------
# Main Execution Block
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Check or create EC2 and run setup script")

    parser.add_argument("--region", required=True, help="AWS region")
    parser.add_argument("--ami-id", required=True, help="AMI ID")
    parser.add_argument("--instance-type", required=True, help="EC2 instance type")
    parser.add_argument("--key-name", required=True, help="Key pair name")
    parser.add_argument("--tag-value", default="fruitstore-ec2", help="EC2 tag value")
    parser.add_argument("--ssh-key-path", required=True, help="Path to SSH private key (PEM)")
    parser.add_argument("--script-path", default="scripts/setup.sh", help="Path to setup script")

    args = parser.parse_args()

    # Step 1: Get or create EC2 instance
    instance_id = get_or_create_instance(
        region=args.region,
        ami_id=args.ami_id,
        instance_type=args.instance_type,
        key_name=args.key_name,
        tag_key="Name",
        tag_value=args.tag_value
    )

    # Step 2: Get public IP
    ip_address = get_instance_public_ip(instance_id, args.region)
    if not ip_address:
        logger.error("Public IP could not be retrieved.")
        exit(1)

    # Step 3: Run setup script via SSH
    run_script_over_ssh(ip_address, args.ssh_key_path, args.script_path)


if __name__ == "__main__":
    main()