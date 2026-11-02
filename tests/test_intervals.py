import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from intervals.client import IntervalsClient, IntervalsSettings
from intervals.utils import sanitize_filename
from myWhoosh2Garmin import is_already_on_garmin, parse_activity_datetime


class TestIntervalsUtils(unittest.TestCase):
    def test_sanitize_filename(self):
        self.assertEqual(
            sanitize_filename("Dubai / Cyclisme: virtuel!"), "Dubai_Cyclisme_virtuel"
        )
        self.assertEqual(sanitize_filename("Test @ Route #1"), "Test_Route_1")
        self.assertEqual(sanitize_filename("  simple_name  "), "simple_name")

    def test_parse_activity_datetime(self):
        dt1 = parse_activity_datetime("2026-11-01T19:26:47")
        self.assertEqual(dt1, datetime(2026, 11, 1, 19, 26, 47))

        dt2 = parse_activity_datetime("2026-11-01 19:26:47Z")
        self.assertEqual(dt2, datetime(2026, 11, 1, 19, 26, 47))

        dt3 = parse_activity_datetime(None)
        self.assertIsNone(dt3)

    def test_is_already_on_garmin(self):
        garmin_times = [
            datetime(2026, 11, 1, 19, 26, 45),  # 2 seconds difference
            datetime(2026, 10, 30, 10, 0, 0),
        ]

        candidate = datetime(2026, 11, 1, 19, 26, 47)
        self.assertTrue(
            is_already_on_garmin(candidate, garmin_times, tolerance_seconds=60)
        )

        candidate_different = datetime(2026, 11, 1, 20, 0, 0)
        self.assertFalse(
            is_already_on_garmin(
                candidate_different, garmin_times, tolerance_seconds=60
            )
        )


class TestIntervalsClient(unittest.TestCase):
    def setUp(self):
        self.settings = IntervalsSettings(
            INTERVALS_ATHLETE_ID="test_athlete",
            INTERVALS_API_KEY="test_key",
        )
        self.client = IntervalsClient(self.settings)

    @patch("intervals.client.requests.Session")
    def test_get_recent_virtual_rides(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        self.client.session = mock_session

        mock_resp = MagicMock()
        mock_resp.json.return_value = [
            {
                "id": "i1",
                "type": "VirtualRide",
                "start_date_local": "2026-11-02T10:00:00",
            },
            {"id": "i2", "type": "Run", "start_date_local": "2026-11-01T10:00:00"},
            {
                "id": "i3",
                "type": "VirtualRide",
                "start_date_local": "2026-10-31T10:00:00",
            },
        ]
        mock_session.get.return_value = mock_resp

        rides = self.client.get_recent_virtual_rides(limit=5)
        self.assertEqual(len(rides), 2)
        self.assertEqual(rides[0]["id"], "i1")
        self.assertEqual(rides[1]["id"], "i3")

    @patch("intervals.client.requests.Session")
    def test_download_fit_file_fallback(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        self.client.session = mock_session

        # First request (/file) fails with 404, second (/fit-file) succeeds with 200
        resp_404 = MagicMock(status_code=404, content=b"")
        resp_200 = MagicMock(status_code=200, content=b"FIT_DATA_BYTES")
        mock_session.get.side_effect = [resp_404, resp_200]

        temp_path = Path("/tmp/test_download_test.fit")
        out_path = self.client.download_fit_file("i123", temp_path)

        self.assertTrue(out_path.exists())
        self.assertEqual(out_path.read_bytes(), b"FIT_DATA_BYTES")
        temp_path.unlink()
