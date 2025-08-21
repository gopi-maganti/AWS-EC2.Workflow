import os
import time
import argparse
import logging

import boto3
import paramiko
from botocore.exceptions import ClientError, WaiterError

# -----------------------------
# Logging Configuration
# -----------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# -----------------------------
# Public key helpers
# -----------------------------
def _load_public_key_from_private(ssh_private_key_path: str) -> str:
    """
    Build an OpenSSH-formatted public key string from a private key file.
    Supports RSA and ECDSA (common for EC2).
    Returns: e.g. 'ssh-rsa AAAAB3...'
    """
    loaders = [
        paramiko.RSAKey.from_private_key_file,
        paramiko.ECDSAKey.from_private_key_file,
        # If your runners have lib for Ed25519, you can enable the next line:
        # paramiko.Ed25519Key.from_private_key_file,
    ]
    last_err: Exception | None = None
    for loader in loaders:
        try:
            key = loader(ssh_private_key_path)
            return f"{key.get_name()} {key.get_base64()}"
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"Unable to parse private key at {ssh_private_key_path}: {last_err}")


def ensure_key_pair(
    region: str,
    key_name: str,
    *,
    public_key_path: str | None = None,
    private_key_path: str | None = None,
) -> None:
    """
    Ensure an EC2 key pair named `key_name` exists in `region`.
    If missing, import using either `public_key_path` (.pub) or derive from `private_key_path` (.pem).
    """
    ec2 = boto3.client("ec2", region_name=region)

    # Already exists?
    try:
        ec2.describe_key_pairs(KeyNames=[key_name])
        logger.info(f"EC2 key pair '{key_name}' already exists in {region}.")
        return
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "InvalidKeyPair.NotFound":
            logger.error(f"Failed describing key pair '{key_name}': {e}")
            raise
        logger.info(f"EC2 key pair '{key_name}' not found; importing...")

    # Build public key material
    if public_key_path and os.path.exists(public_key_path):
        with open(public_key_path, "r", encoding="utf-8") as f:
            public_key_material = f.read().strip()
    elif private_key_path and os.path.exists(private_key_path):
        public_key_material = _load_public_key_from_private(private_key_path)
    else:
        raise ValueError(
            "Provide public_key_path or private_key_path to import the EC2 key pair."
        )

    # Import key
    try:
        ec2.import_key_pair(
            KeyName=key_name,
            PublicKeyMaterial=public_key_material.encode("utf-8"),
        )
        logger.info(f"Imported EC2 key pair '{key_name}' into {region}.")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "InvalidKeyPair.Duplicate":
            logger.info(f"Key pair '{key_name}' created concurrently; continuing.")
        else:
            logger.error(f"Failed to import key pair '{key_name}': {e}")
            raise


# -----------------------------
# Instance helpers
# -----------------------------
def instance_exists(instance_id: str, region: str) -> bool:
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Checking if instance {instance_id} exists in region {region}...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        exists = any(r.get("Instances") for r in response.get("Reservations", []))
        logger.info(
            f"Instance {instance_id} {'exists' if exists else 'does not exist'}."
        )
        return exists
    except ClientError as e:
        logger.error(f"Failed to describe instance {instance_id}: {e}")
        return False


def get_or_create_instance(
    region: str,
    ami_id: str,
    instance_type: str,
    key_name: str,
    *,
    tag_key: str = "Name",
    tag_value: str = "fruitstore-ec2",
    public_key_path: str | None = None,
    private_key_path: str | None = None,
) -> str:
    """Find a running/pending instance by tag; otherwise create one."""
    ec2 = boto3.client("ec2", region_name=region)

    # Ensure KeyPair exists before RunInstances
    try:
        ensure_key_pair(
            region,
            key_name,
            public_key_path=public_key_path,
            private_key_path=private_key_path,
        )
    except Exception:
        logger.error("Could not ensure/import EC2 key pair; aborting instance creation.")
        raise

    # Reuse existing
    try:
        logger.info(
            f"Checking for existing EC2 instance with tag [{tag_key}: {tag_value}] in region {region}..."
        )
        response = ec2.describe_instances(
            Filters=[
                {"Name": f"tag:{tag_key}", "Values": [tag_value]},
                {"Name": "instance-state-name", "Values": ["pending", "running"]},
            ]
        )
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                iid = instance["InstanceId"]
                logger.info(f"Reusing existing instance: {iid}")
                return iid
    except ClientError as e:
        logger.error(f"Error while describing instances: {e}")
        raise

    # Create new
    try:
        logger.info("No existing instance found. Creating new EC2 instance...")
        instances = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": tag_key, "Value": tag_value}],
                }
            ],
        )
        instance_id = instances["Instances"][0]["InstanceId"]
        logger.info(f"Created instance: {instance_id}")

        # Wait until running
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


def get_instance_public_ip(instance_id: str, region: str) -> str | None:
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Fetching public IP for instance {instance_id}...")
        response = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if reservations and reservations[0].get("Instances"):
            ip = reservations[0]["Instances"][0].get("PublicIpAddress")
            logger.info(f"Public IP of instance {instance_id}: {ip}")
            return ip
        logger.warning(f"No public IP found for instance {instance_id}.")
        return None
    except ClientError as e:
        logger.error(f"Failed to get public IP for {instance_id}: {e}")
        return None


# -----------------------------
# SSH + script
# -----------------------------
def run_script_over_ssh(
    ip_address: str, ssh_key_path: str, script_path: str, username: str = "ec2-user"
) -> None:
    logger.info(f"Attempting SSH connection to {ip_address}...")

    try:
        key = paramiko.RSAKey.from_private_key_file(ssh_key_path)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connected = False
        for attempt in range(10):
            try:
                client.connect(
                    hostname=ip_address, username=username, pkey=key, timeout=15
                )
                connected = True
                break
            except Exception as e:
                logger.warning(
                    f"Attempt {attempt + 1}: SSH not ready. Retrying in 6s... ({e})"
                )
                time.sleep(6)

        if not connected:
            raise RuntimeError("SSH connection failed after multiple attempts.")

        logger.info("SSH connection established.")

        with open(script_path, "r", encoding="utf-8") as file:
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
# CLI entrypoint
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Check/create EC2 and run setup script")

    parser.add_argument("--region", required=True, help="AWS region (e.g., us-east-1)")
    parser.add_argument("--ami-id", required=True, help="AMI ID")
    parser.add_argument("--instance-type", required=True, help="EC2 instance type")
    parser.add_argument("--key-name", required=True, help="EC2 Key Pair name")
    parser.add_argument("--tag-value", default="fruitstore-ec2", help="EC2 Name tag")
    parser.add_argument("--ssh-key-path", required=True, help="Path to private key (.pem)")
    parser.add_argument(
        "--public-key-path",
        required=False,
        help="Path to public key (.pub) – preferred if available",
    )
    parser.add_argument(
        "--script-path", default="scripts/setup.sh", help="Path to setup script"
    )

    args = parser.parse_args()

    # 1) Create/reuse instance
    instance_id = get_or_create_instance(
        region=args.region,
        ami_id=args.ami_id,
        instance_type=args.instance_type,
        key_name=args.key_name,
        tag_key="Name",
        tag_value=args.tag_value,
        public_key_path=args.public_key_path,
        private_key_path=args.ssh_key_path,  # used to derive .pub if needed
    )

    # 2) Get public IP
    ip_address = get_instance_public_ip(instance_id, args.region)
    if not ip_address:
        logger.error("Public IP could not be retrieved.")
        raise SystemExit(1)

    # 3) SSH & run script
    run_script_over_ssh(ip_address, args.ssh_key_path, args.script_path)


if __name__ == "__main__":
    main()
