import os
import re
import sys
import time
import tempfile
from datetime import datetime, timezone
import oci

BOOT_VOLUME_GB = 50
DELAY_BETWEEN_REQUESTS = 95  # OCI 90s rate limit එකට වඩා ආරක්ෂිත පරතරය
MAX_RUN_SECONDS = 780        # විනාඩි 13න් ආරක්ෂිතව නතර වී summary ලියයි (හැමවිටම < 15m)

TARGETS = [
    {
        "label": "Micro",
        "display_name": "sg-micro-vps",
        "shape": "VM.Standard.E2.1.Micro",
        "ocpus": None,
        "memory_in_gbs": None,
        "os_version": None,
        "is_arm": False,
    },
    {
        "label": "Ampere A1",
        "display_name": "sg-ampere-a1-vps",
        "shape": "VM.Standard.A1.Flex",
        "ocpus": 1.0,
        "memory_in_gbs": 1.0,
        "os_version": "24.04",
        "is_arm": True,
    },
]


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
        print("Creating Always Free VCN...")
        vcn = network_client.create_vcn(
            oci.core.models.CreateVcnDetails(
                cidr_block="10.0.0.0/16",
                compartment_id=compartment_id,
                display_name="sg-free-vcn",
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
                display_name="sg-free-igw",
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


def find_ubuntu_image(compute_client, compartment_id: str, target: dict):
    """අදාළ Shape එකට ගැළපෙන අලුත්ම Standard Ubuntu Image එක තෝරාගනී."""
    kwargs = {
        "compartment_id": compartment_id,
        "operating_system": "Canonical Ubuntu",
        "shape": target["shape"],
        "sort_by": "TIMECREATED",
        "sort_order": "DESC",
    }
    if target["os_version"]:
        kwargs["operating_system_version"] = target["os_version"]

    images = compute_client.list_images(**kwargs).data
    if not images:
        raise RuntimeError(f"{target['shape']} සඳහා Canonical Ubuntu Image එකක් සොයාගත නොහැකි විය.")

    if target["is_arm"]:
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
            "- `SSH_PUBLIC_KEY` තුළ වැරදීමකින් Private Key එකක් ඇතුළත් කර ඇත! `.pub` Public Key එක පමණක් දමන්න.",
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
    mono_start = time.monotonic()

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
        no_retry = oci.retry.NoneRetryStrategy()
        compute_client = oci.core.ComputeClient(config, retry_strategy=no_retry)
        network_client = oci.core.VirtualNetworkClient(config)
        identity_client = oci.identity.IdentityClient(config)

        summary = [
            "## OCI Singapore Combined Auto-Launch Status",
            f"- **Region:** `{config['region']}` | **Started (UTC):** `{run_start.strftime('%Y-%m-%d %H:%M:%S')}`",
            "",
        ]

        # 1. දැනටමත් හැදිලා තියෙන සර්වර් පරීක්ෂා කිරීම
        instances = compute_client.list_instances(compartment_id=compartment_id).data
        active_instances = [
            inst for inst in instances
            if inst.lifecycle_state not in ("TERMINATED", "TERMINATING")
        ]
        active_shapes = {inst.shape for inst in active_instances}

        if active_instances:
            summary.append("### Active Instances")
            summary.append("| Name | Shape | State | Uptime |")
            summary.append("|---|---|---|---|")
            for inst in active_instances:
                uptime = format_duration(inst.time_created)
                summary.append(
                    f"| `{inst.display_name}` | `{inst.shape}` | **{inst.lifecycle_state}** | `{uptime}` |"
                )
            summary.append("")

        pending_targets = [t for t in TARGETS if t["shape"] not in active_shapes]
        if not pending_targets:
            summary.append(
                "> **Micro සහ Ampere A1 සර්වර් දෙකම සාර්ථකව සෑදී ඇත!** "
                "දැන් GitHub Actions Workflow එක Disable කරන්න."
            )
            write_summary(summary)
            return

        # 2. AD, Subnet, සහ අදාළ OS Images එක් වරක් පමණක් ලබාගැනීම
        ads = identity_client.list_availability_domains(compartment_id=compartment_id).data
        if not ads:
            raise RuntimeError("Availability Domains කිසිවක් සොයාගත නොහැකි විය.")

        subnet, subnet_note = ensure_public_subnet(network_client, compartment_id)
        images_by_shape = {}
        for t in pending_targets:
            images_by_shape[t["shape"]] = find_ubuntu_image(compute_client, compartment_id, t)

        summary.append(f"- **Network:** {subnet_note}")
        for t in pending_targets:
            summary.append(f"- **{t['label']} Image:** `{images_by_shape[t['shape']].display_name}`")

        summary.extend([
            "",
            "### Launch Attempts (95s Alternating Spacing)",
            "| # | Time (UTC) | Target | AD | Result |",
            "|---|---|---|---|---|",
        ])

        # Target 2ක් තියෙනවා නම් 4 බැගින් (මුළු 8ක් = ~11.5m); 1ක් නම් 5ක් (~6.5m)
        attempts_per_target = 4 if len(pending_targets) > 1 else 5
        launch_queue = []
        for _ in range(attempts_per_target):
            for t in pending_targets:
                launch_queue.append(t)

        done_shapes = set()
        created_instances = []
        step_num = 0

        for idx, target in enumerate(launch_queue):
            if target["shape"] in done_shapes:
                continue

            ad = ads[0]
            step_num += 1
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            ad_short = ad.name.split(":")[-1]
            print(f"[Step {step_num}] Launching {target['shape']} ({target['display_name']}) in {ad_short}...")

            launch_kwargs = {
                "availability_domain": ad.name,
                "compartment_id": compartment_id,
                "display_name": target["display_name"],
                "shape": target["shape"],
                "source_details": oci.core.models.InstanceSourceViaImageDetails(
                    source_type="image",
                    image_id=images_by_shape[target["shape"]].id,
                    boot_volume_size_in_gbs=BOOT_VOLUME_GB,
                ),
                "create_vnic_details": oci.core.models.CreateVnicDetails(
                    subnet_id=subnet.id,
                    assign_public_ip=True,
                ),
                "metadata": {
                    "ssh_authorized_keys": ssh_public_key,
                },
            }
            if target["ocpus"] is not None and target["memory_in_gbs"] is not None:
                launch_kwargs["shape_config"] = oci.core.models.LaunchInstanceShapeConfigDetails(
                    ocpus=target["ocpus"],
                    memory_in_gbs=target["memory_in_gbs"],
                )

            launch_details = oci.core.models.LaunchInstanceDetails(**launch_kwargs)

            try:
                resp = compute_client.launch_instance(
                    launch_instance_details=launch_details,
                    retry_strategy=no_retry,
                )
                inst = resp.data
                created_instances.append(inst)
                done_shapes.add(target["shape"])
                summary.append(
                    f"| {step_num} | `{ts}` | `{target['label']}` | `{ad_short}` | **SUCCESS (`{inst.lifecycle_state}`)** |"
                )
                print(f"  -> SUCCESS! {inst.display_name} created ({inst.lifecycle_state})")

            except oci.exceptions.ServiceError as e:
                msg = str(e.message or "")
                if "Out of host capacity" in msg or "Out of capacity" in msg:
                    status_text = "Out of host capacity (ඉඩ නැත)"
                elif e.status == 429 or e.code == "TooManyRequests":
                    status_text = f"TooManyRequests ({redact_sensitive(msg)[:100]})"
                elif e.code == "LimitExceeded":
                    status_text = f"LimitExceeded ({redact_sensitive(msg)[:100]})"
                    done_shapes.add(target["shape"])
                else:
                    status_text = f"HTTP {e.status} ({e.code}): {redact_sensitive(msg)[:100]}"
                    if e.status in (401, 403, 404):
                        summary.append(
                            f"| {step_num} | `{ts}` | `{target['label']}` | `{ad_short}` | {status_text} |"
                        )
                        write_summary(summary)
                        sys.exit(1)
                    done_shapes.add(target["shape"])

                print(f"  -> {status_text}")
                summary.append(
                    f"| {step_num} | `{ts}` | `{target['label']}` | `{ad_short}` | {status_text} |"
                )

            # තව ඉතුරු targets තියෙනවද සහ ඊළඟ sleep එකෙන් පස්සේ 13m ඉක්මවනවද බැලීම
            has_more = any(t["shape"] not in done_shapes for t in launch_queue[idx + 1:])
            if not has_more:
                break

            elapsed = time.monotonic() - mono_start
            if elapsed + DELAY_BETWEEN_REQUESTS > MAX_RUN_SECONDS:
                print("Approaching 13m safety cap; ending run cleanly.")
                break

            print(f"Waiting {DELAY_BETWEEN_REQUESTS}s before next launch request...")
            time.sleep(DELAY_BETWEEN_REQUESTS)

        total_dur = format_duration(run_start)
        summary.append("")
        if created_instances:
            names = ", ".join(f"`{i.display_name}` (`{i.shape}`)" for i in created_instances)
            summary.append(
                f"> **සුභ පැතුම්!** {names} සාර්ථකව නිර්මාණය වෙමින් පවතී! Oracle Console එකෙන් Public IP එක ලබාගන්න."
            )
        summary.append(f"- **Run Duration:** `{total_dur}`")

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
