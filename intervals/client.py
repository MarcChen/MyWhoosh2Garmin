import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class IntervalsSettings(BaseSettings):
    """Configuration settings for Intervals.icu client."""

    athlete_id: str = Field(..., alias="INTERVALS_ATHLETE_ID")
    api_key: SecretStr = Field(..., alias="INTERVALS_API_KEY")

    model_config = SettingsConfigDict(
        env_file=Path(__file__).parent.parent / ".env",
        extra="ignore",
    )


class IntervalsClient:
    """Client for Intervals.icu REST API."""

    BASE_URL = "https://intervals.icu/api/v1"

    def __init__(self, settings: Optional[IntervalsSettings] = None):
        self.settings = settings or IntervalsSettings()
        self.session = requests.Session()
        self.session.auth = ("API_KEY", self.settings.api_key.get_secret_value())

    def get_athlete(self) -> Dict[str, Any]:
        """Fetch athlete profile."""
        url = f"{self.BASE_URL}/athlete/{self.settings.athlete_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_activity(self, activity_id: str) -> Dict[str, Any]:
        """Fetch details for a specific activity."""
        url = f"{self.BASE_URL}/activity/{activity_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def get_recent_virtual_rides(
        self, limit: int = 5, oldest_days: int = 14
    ) -> List[Dict[str, Any]]:
        """Fetch recent VirtualRide activities."""
        oldest_date = (
            datetime.now(timezone.utc) - timedelta(days=oldest_days)
        ).strftime("%Y-%m-%d")
        url = f"{self.BASE_URL}/athlete/{self.settings.athlete_id}/activities"
        resp = self.session.get(url, params={"oldest": oldest_date})
        resp.raise_for_status()

        activities = resp.json()
        virtual_rides = [act for act in activities if act.get("type") == "VirtualRide"]
        # Sort descending by start date
        virtual_rides.sort(
            key=lambda x: x.get("start_date_local") or x.get("start_date") or "",
            reverse=True,
        )
        return virtual_rides[:limit]

    def download_fit_file(self, activity_id: str, dest_path: Path) -> Path:
        """
        Download the .fit file for an activity.
        First tries original /file endpoint, falls back to /fit-file.
        """
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Try original uploaded file
        original_url = f"{self.BASE_URL}/activity/{activity_id}/file"
        logger.info("Attempting download from original file: %s", original_url)
        resp = self.session.get(original_url)

        if resp.status_code == 200 and resp.content:
            dest_path.write_bytes(resp.content)
            logger.info(
                "Downloaded original .fit file to %s (%d bytes)",
                dest_path,
                len(resp.content),
            )
            return dest_path

        # 2. Fallback to /fit-file endpoint
        logger.warning(
            "Original file endpoint returned %s; falling back to /fit-file",
            resp.status_code,
        )
        fallback_url = f"{self.BASE_URL}/activity/{activity_id}/fit-file"
        resp_fallback = self.session.get(fallback_url)
        resp_fallback.raise_for_status()

        dest_path.write_bytes(resp_fallback.content)
        logger.info(
            "Downloaded standardized .fit file to %s (%d bytes)",
            dest_path,
            len(resp_fallback.content),
        )
        return dest_path
