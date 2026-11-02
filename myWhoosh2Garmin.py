import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

from dotenv import load_dotenv

from garmin.utils import (
    authenticate_to_garmin,
    list_virtual_cycling_activities,
    upload_fit_file_to_garmin,
)
from intervals.client import IntervalsClient
from intervals.utils import sanitize_filename

load_dotenv()

SCRIPT_DIR = Path(__file__).resolve().parent
log_file_path = SCRIPT_DIR / "myWhoosh2Garmin.log"
PROCESSED_FIT_PATH = SCRIPT_DIR / "data" / "processed"

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(log_file_path)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Also log to stdout
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def parse_activity_datetime(dt_val: Any) -> Optional[datetime]:
    """Parse start date into a timezone-naive datetime."""
    if not dt_val:
        return None
    if isinstance(dt_val, (int, float)):
        return datetime.fromtimestamp(dt_val)
    if isinstance(dt_val, str):
        # Remove Z or timezone offset if present
        clean_str = dt_val.split("+")[0].split("Z")[0]
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(clean_str, fmt)
            except ValueError:
                continue
    return None


def is_already_on_garmin(
    candidate_dt: Optional[datetime],
    garmin_start_times: List[datetime],
    tolerance_seconds: int = 60,
) -> bool:
    """Check if a candidate activity start time matches an existing Garmin activity."""
    if not candidate_dt:
        return False

    for existing_dt in garmin_start_times:
        if not existing_dt:
            continue
        # Strip timezone if present
        naive_existing = (
            existing_dt.replace(tzinfo=None) if existing_dt.tzinfo else existing_dt
        )
        naive_candidate = (
            candidate_dt.replace(tzinfo=None) if candidate_dt.tzinfo else candidate_dt
        )
        delta = abs((naive_existing - naive_candidate).total_seconds())
        if delta <= tolerance_seconds:
            return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Sync MyWhoosh virtual rides from Intervals.icu to Garmin Connect."
    )
    parser.add_argument(
        "--activity-id",
        default="",
        help="Optional Intervals.icu activity ID (e.g. i204876551). "
        "If omitted, checks the last 5 activities.",
    )
    args = parser.parse_args()

    authenticate_to_garmin()
    intervals_client = IntervalsClient()

    # Determine candidate activities
    if args.activity_id.strip():
        act_id = args.activity_id.strip()
        logger.info("Fetching specific activity from Intervals.icu: %s", act_id)
        candidate_activities = [intervals_client.get_activity(act_id)]
    else:
        logger.info("Scanning Intervals.icu for the last 5 VirtualRide activities...")
        candidate_activities = intervals_client.get_recent_virtual_rides(limit=5)

    if not candidate_activities:
        logger.info("No candidate activities found to sync.")
        return

    # Retrieve existing Garmin virtual cycling activities for idempotency check
    _, garmin_start_times = list_virtual_cycling_activities(last_n_days=14)

    uploaded_count = 0
    for activity in candidate_activities:
        act_id = str(activity.get("id", ""))
        act_name = activity.get("name", "MyWhoosh Ride")
        raw_start = activity.get("start_date_local") or activity.get("start_date")
        act_dt = parse_activity_datetime(raw_start)

        # Idempotency check: Skip if already present on Garmin Connect
        if is_already_on_garmin(act_dt, garmin_start_times, tolerance_seconds=60):
            logger.info(
                "Activity '%s' (ID: %s, Start: %s) already in Garmin. Skipping.",
                act_name,
                act_id,
                act_dt,
            )
            continue

        # Download .fit file from Intervals.icu
        safe_name = sanitize_filename(act_name)
        fit_path = PROCESSED_FIT_PATH / f"{safe_name}_{act_id}.fit"
        logger.info("Downloading .fit for activity '%s' (%s)...", act_name, act_id)
        intervals_client.download_fit_file(act_id, fit_path)

        # Upload to Garmin Connect
        logger.info("Uploading %s to Garmin Connect...", fit_path)
        upload_fit_file_to_garmin(fit_path)
        uploaded_count += 1

        # Delete temporary file
        try:
            fit_path.unlink(missing_ok=True)
            logger.info("Cleaned up temporary file: %s", fit_path)
        except Exception as e:
            logger.warning("Could not delete %s: %e", fit_path, e)

    logger.info("Sync complete. Uploaded %d new activity/activities.", uploaded_count)


if __name__ == "__main__":
    main()
