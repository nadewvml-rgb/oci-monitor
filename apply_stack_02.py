import os
import re
import sys
import time
import tempfile
from datetime import datetime, timezone
import oci

TARGET_SHAPE = "VM.Standard.A1.Flex"
OCPUS = 1.0
MEMORY_IN_GBS = 1.0
INSTANCE_DISPLAY_NAME = "sg-ampere-a1-vps"
BOOT_VOLUME_GB = 50
ATTEMPTS_PER_RUN = 5
BASE_DELAY_SECONDS = 140


def redact_sensitive(text: str) -> str:
    """Public repo logs වලට OCID හෝ IP ලිපින යාම වළක්වයි."""
    if not text:
        return ""
    text = re.sub(r"ocid1\.[a-zA-Z0-9._-]+", "[REDACTED_OCID]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]", text)
    return text


def format_duration(start_dt, end_dt=None) -> str:
    if not start_dt:
        return "N/A"
    end_dt = end_dt or datetime.now(timezone.utc)
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=timezone.utc)
    seconds = max(0, int((end_dt - start_dt).total_seconds()))
    mins, secs = divmod(seconds, 60)
    hrs, mins = divmod(mins, 60)
    if hrs > 0:
        return f"{hrs}h {mins}m {secs}s"
    return f"{mins}m {secs}s"


def write_summary(lines: list[str]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    content = "\n".join(lines) + "\n"
    print("\n" + content)
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(content)


def ensure_public_subnet(network_client, compartment_id: str) -> tuple:
    """දැනට ඇති Public Subnet එක සොයාගනී; නොමැති නම් නව VCN + IGW + Public Subnet එකක් ස්වයංක්‍රීයව සාදයි."""
    subnets = network_client.list_subnets(compartment_id=compartment_id).data
    for s in subnets:
        if s.lifecycle_state == "AVAILABLE" and not s.prohibit_public_ip_on_vnic:
            return s, f"Existing subnet (`{s.display_name}`)"

    vcns = [
        v for v in network_client.list_vcns(compartment_id=compartment_id).data
        if v.lifecycle_state == "AVAILABLE"
    ]
    if vcns:
        vcn = vcns[0]
        vcn_note = f"existing VCN `{vcn.display_name}`"
    else:
        print("Creating VCN...")
        vcn = network_client.create_vcn(
            oci.core.models.CreateVcnDetails(
                cidr_block="10.0.0.0/16",
                compartment_id=compartment_id,
                display_name="sg-a1-vcn",
            )
        ).data
        vcn = oci.wait_until(
            network_client,
            network_client.get_vcn(vcn.id),
            "lifecycle_state",
            "AVAILABLE",
        ).data
        vcn_note = "newly created VCN"

    igws = [
        g for g in network_client.list_internet_gateways(
            compartment_id=compartment_id, vcn_id=vcn.id
        ).data
        if g.lifecycle_state == "AVAILABLE"
    ]
    if igws:
        igw = igws[0]
    else:
        print("Creating Internet Gateway...")
        igw = network_client.create_internet_gateway(
            oci.core.models.CreateInternetGatewayDetails(
                compartment_id=compartment_id,
                display_name="sg-a1-igw",
                is_enabled=True,
                vcn_id=vcn.id,
            )
        ).data
        igw = oci.wait_until(
            network_client,
            network_client.get_internet_gateway(igw.id),
            "lifecycle_state",
            "AVAILABLE",
        ).data

    rt = network_client.get_route_table(vcn.default_route_table_id).data
    has_default_route = any(
        r.destination == "0.0.0.0/0" for r in (rt.route_rules or [])
    )
    if not has_default_route:
        print("Adding 0.0.0.0/0 internet route...")
        rules = list(rt.route_rules or [])
        rules.append(
            oci.core.models.RouteRule(
                destination="0.0.0.0/0",
                destination_type="CIDR_BLOCK",
                network_entity_id=igw.id,
            )
        )
        network_client.update_route_table(
            rt_id=vcn.default_route_table_id,
            update_route_table_details=oci.core.models.UpdateRouteTableDetails(
                route_rules=rules
            ),
        )

    existing_cidrs = {s.cidr_block for s in subnets if s.vcn_id == vcn.id}
    vcn_prefix = ".".join(vcn.cidr_block.split(".")[:2])
    subnet_cidr = None
    for octet in range(0, 255):
        candidate = f"{vcn_prefix}.{octet}.0/24"
        if candidate not in existing_cidrs:
            subnet_cidr = candidate
            break
    if not subnet_cidr:
        raise RuntimeError("Existing VCN තුළ හිස් /24 CIDR පරාසයක් සොයාගත නොහැකි විය.")

    print("Creating Public Subnet...")
    subnet = network_client.create_subnet(
        oci.core.models.CreateSubnetDetails(
            cidr_block=subnet_cidr,
            compartment_id=compartment_id,
            display_name="sg-public-subnet",
            vcn_id=vcn.id,
            route_table_id=vcn.default_route_table_id,
            security_list_ids=[vcn.default_security_list_id],
            prohibit_public_ip_on_vnic=False,
        )
    ).data
    subnet = oci.wait_until(
        network_client,
        network_client.get_subnet(subnet.id),
        "lifecycle_state",
        "AVAILABLE",
    ).data
    return subnet, f"Auto-created public subnet in {vcn_note}"


def find_ubuntu_2404_arm_image(compute_client, compartment_id: str):
    """VM.Standard.A1.Flex සඳහා ගැළපෙන අලුත්ම Standard Canonical Ubuntu 24.04 (ARM / aarch64) Image එක තෝරාගනී."""
    images = compute_client.list_images(
        compartment_id=compartment_id,
        operating_system="Canonical Ubuntu",
        operating_system_version="24.04",
        shape=TARGET_SHAPE,
        sort_by="TIMECREATED",
        sort_order="DESC",
    ).data
    if not images:
        raise RuntimeError(
            f"{TARGET_SHAPE} සඳහා Canonical Ubuntu 24.04 (ARM / aarch64) Image එකක් සොයාගත නොහැකි විය."
        )

    for img in images:
        name = (img.display_name or "").lower()
        if "aarch64" in name and "minimal" not in name and "gpu" not in name:
            return img

    for img in images:
        name = (img.display_name or "").lower()
        if "minimal" not in name and "gpu" not in name:
            return img

    return images[0]


def main():
    required_vars = [
        "OCI_USER_OCID",
        "OCI_FINGERPRINT",
        "OCI_TENANCY_OCID",
        "OCI_REGION",
        "OCI_PRIVATE_KEY",
        "SSH_PUBLIC_KEY",
    ]
    missing = [v for v in required_vars if not os.environ.get(v)]
    if missing:
        write_summary([
            "## Missing GitHub Secrets",
            f"- අඩු Secrets: `{', '.join(missing)}`",
        ])
        sys.exit(1)

    ssh_public_key = os.environ["SSH_PUBLIC_KEY"].strip()
    if "PRIVATE KEY" in ssh_public_key:
        write_summary([
            "## SSH Key Error",
            "- `SSH_PUBLIC_KEY` තුළ වැරදීමකින් Private Key එකක් ඇතුළත් කර ඇත! කරුණාකර `.pub` ගොනුවේ ඇති Public Key එක (`ssh-ed25519 ...`) පමණක් දමන්න.",
        ])
        sys.exit(1)
    if not ssh_public_key.startswith(("ssh-", "ecdsa-", "sk-")):
        write_summary([
            "## SSH Key Error",
            "- `SSH_PUBLIC_KEY` අගය `ssh-ed25519` හෝ `ssh-rsa` ලෙස ආරම්භ විය යුතුය.",
        ])
        sys.exit(1)

    key_content = os.environ["OCI_PRIVATE_KEY"].strip()
    key_fd, key_path = tempfile.mkstemp(prefix="oci_key_", suffix=".pem")
    run_start = datetime.now(timezone.utc)

    try:
        with os.fdopen(key_fd, "w", encoding="utf-8") as f:
            f.write(key_content + "\n")
        os.chmod(key_path, 0o600)

        config = {
            "user": os.environ["OCI_USER_OCID"].strip(),
            "fingerprint": os.environ["OCI_FINGERPRINT"].strip(),
            "tenancy": os.environ["OCI_TENANCY_OCID"].strip(),
            "region": os.environ["OCI_REGION"].strip(),
            "key_file": key_path,
        }
        oci.config.validate_config(config)

        compartment_id = config["tenancy"]
        # NoneRetryStrategy: HTTP 500 (Out of host capacity) වලට SDK එක ඇතුළෙන් retry වීම නවතයි
        no_retry = oci.retry.NoneRetryStrategy()
        compute_client = oci.core.ComputeClient(config, retry_strategy=no_retry)
        network_client = oci.core.VirtualNetworkClient(config)
        identity_client = oci.identity.IdentityClient(config)

        summary = [
            "## OCI Ampere A1 Auto-Launch Status",
            f"- **Region:** `{config['region']}` | **Target Shape:** `{TARGET_SHAPE}` (`{int(OCPUS)} OCPU / {int(MEMORY_IN_GBS)} GB RAM`)",
            f"- **Started (UTC):** `{run_start.strftime('%Y-%m-%d %H:%M:%S')}`",
            "",
        ]

        # 1. දැනටමත් VM.Standard.A1.Flex සර්වර් එකක් හැදිලා තියෙනවදැයි පරීක්ෂා කිරීම
        instances = compute_client.list_instances(compartment_id=compartment_id).data
        active_target_instances = [
            inst for inst in instances
            if inst.lifecycle_state not in ("TERMINATED", "TERMINATING")
            and inst.shape == TARGET_SHAPE
        ]
        if active_target_instances:
            summary.append("### Ampere A1 Instance Already Active!")
            summary.append("| Name | Shape | Specs | State | Uptime |")
            summary.append("|---|---|---|---|---|")
            for inst in active_target_instances:
                uptime = format_duration(inst.time_created)
                sc = getattr(inst, "shape_config", None)
                specs = (
                    f"{sc.ocpus:g} OCPU / {sc.memory_in_gbs:g} GB"
                    if sc and sc.ocpus and sc.memory_in_gbs
                    else "N/A"
                )
                summary.append(
                    f"| `{inst.display_name}` | `{inst.shape}` | `{specs}` | **{inst.lifecycle_state}** | `{uptime}` |"
                )
            summary.append("")
            summary.append(
                "> Ampere A1 සර්වර් එක සාර්ථකව සෑදී ඇත! තවදුරටත් උත්සාහ නොකර නතර වේ."
            )
            write_summary(summary)
            return

        # 2. Availability Domains, Subnet, සහ Ubuntu 24.04 ARM Image සූදානම් කරගැනීම
        ads = identity_client.list_availability_domains(compartment_id=compartment_id).data
        if not ads:
            raise RuntimeError("Availability Domains කිසිවක් සොයාගත නොහැකි විය.")

        subnet, subnet_note = ensure_public_subnet(network_client, compartment_id)
        image = find_ubuntu_2404_arm_image(compute_client, compartment_id)

        summary.extend([
            f"- **Active `{TARGET_SHAPE}` Instances:** `0`",
            f"- **Network:** {subnet_note}",
            f"- **OS Image:** `{image.display_name}`",
            f"- **Boot Volume:** `{BOOT_VOLUME_GB} GB`",
            "",
            "### Launch Attempts",
            "| # | Time (UTC) | AD | Result |",
            "|---|---|---|---|",
        ])

        created_instance = None
        stop_early = False

        for attempt in range(1, ATTEMPTS_PER_RUN + 1):
            for ad in ads:
                ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                ad_short = ad.name.split(":")[-1]
                print(
                    f"[Attempt {attempt}/{ATTEMPTS_PER_RUN}] Launching {TARGET_SHAPE} "
                    f"({int(OCPUS)} OCPU / {int(MEMORY_IN_GBS)} GB) in {ad_short}..."
                )

                launch_details = oci.core.models.LaunchInstanceDetails(
                    availability_domain=ad.name,
                    compartment_id=compartment_id,
                    display_name=INSTANCE_DISPLAY_NAME,
                    shape=TARGET_SHAPE,
                    shape_config=oci.core.models.LaunchInstanceShapeConfigDetails(
                        ocpus=OCPUS,
                        memory_in_gbs=MEMORY_IN_GBS,
                    ),
                    source_details=oci.core.models.InstanceSourceViaImageDetails(
                        source_type="image",
                        image_id=image.id,
                        boot_volume_size_in_gbs=BOOT_VOLUME_GB,
                    ),
                    create_vnic_details=oci.core.models.CreateVnicDetails(
                        subnet_id=subnet.id,
                        assign_public_ip=True,
                    ),
                    metadata={
                        "ssh_authorized_keys": ssh_public_key,
                    },
                )

                try:
                    resp = compute_client.launch_instance(
                        launch_instance_details=launch_details,
                        retry_strategy=no_retry,
                    )
                    created_instance = resp.data
                    summary.append(
                        f"| {attempt} | `{ts}` | `{ad_short}` | **SUCCESS (`{created_instance.lifecycle_state}`)** |"
                    )
                    print(f"SUCCESS! Instance created in state: {created_instance.lifecycle_state}")
                    stop_early = True
                    break

                except oci.exceptions.ServiceError as e:
                    msg = str(e.message or "")
                    if "Out of host capacity" in msg or "Out of capacity" in msg:
                        status_text = "Out of host capacity (ඉඩ නැත)"
                        print(f"  -> {status_text}")
                        summary.append(f"| {attempt} | `{ts}` | `{ad_short}` | {status_text} |")
                    elif e.status == 429 or e.code == "TooManyRequests":
                        status_text = "TooManyRequests (ඊළඟ වටය තෙක් රැඳී සිටී)"
                        print(f"  -> {status_text}")
                        summary.append(f"| {attempt} | `{ts}` | `{ad_short}` | {status_text} |")
                    elif e.code == "LimitExceeded":
                        status_text = f"LimitExceeded ({redact_sensitive(msg)[:120]})"
                        print(f"  -> {status_text}")
                        summary.append(f"| {attempt} | `{ts}` | `{ad_short}` | {status_text} |")
                        stop_early = True
                        break
                    else:
                        status_text = f"HTTP {e.status} ({e.code}): {redact_sensitive(msg)[:120]}"
                        print(f"  -> {status_text}")
                        summary.append(f"| {attempt} | `{ts}` | `{ad_short}` | {status_text} |")
                        if e.status in (401, 403, 404):
                            write_summary(summary)
                            sys.exit(1)
                        stop_early = True
                        break

            if stop_early:
                break

            if attempt < ATTEMPTS_PER_RUN:
                print(f"Waiting {BASE_DELAY_SECONDS}s before next attempt...")
                time.sleep(BASE_DELAY_SECONDS)

        total_dur = format_duration(run_start)
        summary.append("")
        if created_instance:
            summary.append(
                f"> **සුභ පැතුම්!** `{created_instance.display_name}` (`{TARGET_SHAPE}` - "
                f"`{int(OCPUS)} OCPU / {int(MEMORY_IN_GBS)} GB RAM`) සාර්ථකව නිර්මාණය වෙමින් පවතී! "
                f"Oracle Console එකෙන් Public IP එක ලබාගන්න."
            )
        else:
            summary.append(f"- **Run Duration:** `{total_dur}` (ඊළඟ වටයේදී නැවත උත්සාහ කරයි)")

        write_summary(summary)

    except oci.exceptions.ServiceError as e:
        write_summary([
            "## OCI API Error",
            f"- **Operation:** `{getattr(e, 'operation_name', 'N/A')}`",
            f"- **HTTP Status:** `{e.status}`",
            f"- **Code:** `{e.code}`",
            f"- **Message:** {redact_sensitive(str(e.message))}",
        ])
        if e.status in (400, 401, 403, 404):
            sys.exit(1)
    except RuntimeError as e:
        write_summary([
            "## Setup Notice",
            f"- {redact_sensitive(str(e))}",
        ])
        sys.exit(1)
    finally:
        if os.path.exists(key_path):
            os.remove(key_path)


if __name__ == "__main__":
    main()
