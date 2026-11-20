import os
import re
import sys
import time
import tempfile
from datetime import datetime, timezone
import oci

POLL_INTERVAL_SECONDS = 20
MAX_WAIT_SECONDS = 900  # උපරිම විනාඩි 15ක් එක Job එකක ප්‍රතිඵලය එනකම් බලන් ඉන්නවා


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


def extract_error_reason(rm_client, job_id: str, job_obj) -> str:
    """Job එක Fail වුණු නිශ්චිත හේතුව (උදා: Out of host capacity) පමණක් වෙන්කර ගනී."""
    try:
        logs = rm_client.get_job_logs_content(job_id=job_id).data
        if isinstance(logs, bytes):
            logs = logs.decode("utf-8", errors="ignore")
        if logs:
            if "Out of host capacity" in logs or "Out of capacity" in logs:
                return "Out of host capacity (Singapore වල දැනට ඉඩ නැත)"
            if "TooManyRequests" in logs:
                return "TooManyRequests (API සීමාව - ඊළඟ වටයේ නැවත උත්සාහ කරයි)"
            if "LimitExceeded" in logs:
                return "LimitExceeded (Free Tier සීමාව ඉක්මවා ඇත)"
            for line in logs.splitlines():
                if "Error:" in line or "ServiceError" in line:
                    return redact_sensitive(line.strip())[:180]
    except Exception:
        pass

    failure = getattr(job_obj, "failure_details", None)
    if failure and getattr(failure, "message", None):
        return redact_sensitive(str(failure.message))[:180]
    return "Unknown failure (Check job state)"


def wait_for_job(rm_client, job_id: str) -> tuple:
    """Job එක අවසන් වන තුරු බලා සිටී."""
    start_wait = time.time()
    while True:
        job = rm_client.get_job(job_id=job_id).data
        state = job.lifecycle_state
        elapsed = format_duration(job.time_created, job.time_finished)
        print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}] Job State: {state} | Elapsed: {elapsed}")

        if state not in ("ACCEPTED", "IN_PROGRESS"):
            return job, False

        if (time.time() - start_wait) >= MAX_WAIT_SECONDS:
            print("Max wait limit reached. Exiting cleanly so the next scheduled run continues tracking.")
            return job, True

        time.sleep(POLL_INTERVAL_SECONDS)


def main():
    required_vars = [
        "OCI_USER_OCID",
        "OCI_FINGERPRINT",
        "OCI_TENANCY_OCID",
        "OCI_REGION",
        "OCI_STACK_OCID",
        "OCI_PRIVATE_KEY",
    ]
    missing = [v for v in required_vars if not os.environ.get(v)]
    if missing:
        print(f"Missing required GitHub Secrets: {', '.join(missing)}")
        sys.exit(1)

    stack_id = os.environ["OCI_STACK_OCID"].strip()
    key_content = os.environ["OCI_PRIVATE_KEY"].strip()

    key_fd, key_path = tempfile.mkstemp(prefix="oci_key_", suffix=".pem")
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

        rm_client = oci.resource_manager.ResourceManagerClient(config)
        compute_client = oci.core.ComputeClient(config)

        # 1. Stack තොරතුරු සහ Compartment OCID ලබාගැනීම
        stack = rm_client.get_stack(stack_id=stack_id).data
        compartment_id = stack.compartment_id

        summary = [
            "## OCI Singapore Auto-Apply Status",
            f"- **Region:** `{config['region']}`",
            f"- **Stack State:** `{stack.lifecycle_state}`",
            f"- **Checked At (UTC):** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}`",
            "",
        ]

        # 2. දැනටමත් Instance එකක් හැදිලා තියෙනවදැයි පරීක්ෂා කිරීම
        instances = compute_client.list_instances(compartment_id=compartment_id).data
        active_instances = [
            inst for inst in instances
            if inst.lifecycle_state not in ("TERMINATED", "TERMINATING")
        ]

        if active_instances:
            summary.append("### Instance Created / Active!")
            summary.append("| Name | Shape | State | Uptime |")
            summary.append("|---|---|---|---|")
            for inst in active_instances:
                uptime = format_duration(inst.time_created)
                summary.append(
                    f"| `{inst.display_name}` | `{inst.shape}` | **{inst.lifecycle_state}** | `{uptime}` |"
                )
            summary.append("")
            summary.append(
                "> සර්වර් එක සාර්ථකව සෑදී ඇත! තවදුරටත් Apply නොකර නතර වේ. "
                "දැන් GitHub Actions Workflow එක Disable කරන්න."
            )
            write_summary(summary)
            return

        summary.append("- **Active Instances:** `0` (තවම සර්වර් එක සෑදී නැත)")

        # 3. දැනට Queue වී හෝ ක්‍රියාත්මක වෙමින් පවතින Job එකක් තිබේදැයි පරීක්ෂා කිරීම
        recent_jobs = rm_client.list_jobs(
            stack_id=stack_id,
            sort_by="TIMECREATED",
            sort_order="DESC",
            limit=5,
        ).data

        running_job = next(
            (j for j in recent_jobs if j.lifecycle_state in ("ACCEPTED", "IN_PROGRESS")),
            None,
        )

        if running_job:
            print(f"Found an already active job ({running_job.lifecycle_state}). Waiting for it to finish...")
            final_job, timed_out = wait_for_job(rm_client, running_job.id)
            action_note = "Tracked existing active job"
        else:
            print("No active job found. Triggering a new APPLY job...")
            create_details = oci.resource_manager.models.CreateJobDetails(
                stack_id=stack_id,
                display_name="auto-apply-gh",
                job_operation_details=oci.resource_manager.models.CreateApplyJobOperationDetails(
                    execution_plan_strategy="AUTO_APPROVED"
                ),
            )
            new_job = rm_client.create_job(create_job_details=create_details).data
            final_job, timed_out = wait_for_job(rm_client, new_job.id)
            action_note = "Triggered new APPLY job"

        duration = format_duration(final_job.time_created, final_job.time_finished)
        reason = ""
        if final_job.lifecycle_state == "FAILED":
            reason = extract_error_reason(rm_client, final_job.id, final_job)
        elif final_job.lifecycle_state == "SUCCEEDED":
            reason = "SUCCESS! සර්වර් එක සාර්ථකව නිර්මාණය විය!"
        elif timed_out:
            reason = "තවමත් පෝලිමේ/ක්‍රියාත්මක වෙමින් පවතී (ඊළඟ වටයේදී නැවත පරීක්ෂා කරයි)"

        summary.extend([
            "",
            "### Current Run Result",
            "| Action | Job State | Duration | Details |",
            "|---|---|---|---|",
            f"| {action_note} | **{final_job.lifecycle_state}** | `{duration}` | {reason} |",
            "",
            "### Recent Job History",
            "| Operation | State | Started (UTC) | Duration |",
            "|---|---|---|---|",
        ])

        updated_jobs = rm_client.list_jobs(
            stack_id=stack_id,
            sort_by="TIMECREATED",
            sort_order="DESC",
            limit=3,
        ).data
        for j in updated_jobs:
            j_start = j.time_created.strftime("%m-%d %H:%M") if j.time_created else "N/A"
            j_dur = format_duration(j.time_created, j.time_finished)
            summary.append(f"| `{j.operation}` | `{j.lifecycle_state}` | `{j_start}` | `{j_dur}` |")

        write_summary(summary)

    except oci.exceptions.ServiceError as e:
        safe_msg = redact_sensitive(str(e.message))
        write_summary([
            "## OCI API Notice",
            f"- **HTTP Status:** `{e.status}`",
            f"- **Code:** `{e.code}`",
            f"- **Message:** {safe_msg}",
        ])
        # Auth errors (401/404) වලදී පමණක් Workflow එක Fail කරයි; Rate limit (429) වලදී ඊළඟ වටයට ඉඩ දෙයි.
        if e.status in (401, 404):
            sys.exit(1)
    finally:
        if os.path.exists(key_path):
            os.remove(key_path)


if __name__ == "__main__":
    main()
