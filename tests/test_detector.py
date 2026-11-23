from io import StringIO
import pandas as pd
import pytest
from detector import load_logs, detect_brute_force, summarize_logs


def make_logs(events):
    df = pd.DataFrame(events, columns=["timestamp", "ip_address", "username", "status"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    return df


def test_detect_five_failed_logins():
    logs = make_logs([(f"2026-11-23 10:0{i}:00", "192.0.2.10", "admin", "failed") for i in range(5)])
    alerts = detect_brute_force(logs)
    assert len(alerts) == 1
    assert alerts.iloc[0]["failed_attempts"] == 5
    assert alerts.iloc[0]["severity"] == "High"


def test_no_alert_for_successful_logins():
    assert detect_brute_force(make_logs([("2026-11-23 10:00:00", "192.0.2.10", "alice", "success")])).empty


def test_no_alert_outside_time_window():
    logs = make_logs([(f"2026-11-23 10:{i*10:02d}:00", "192.0.2.10", "admin", "failed") for i in range(5)])
    assert detect_brute_force(logs).empty


def test_load_logs_removes_invalid_rows():
    source = StringIO("timestamp,ip_address,username,status\n2026-11-23 10:00:00,192.0.2.10,admin,failed\ninvalid-date,192.0.2.10,admin,failed\n2026-11-23 10:01:00,invalid-ip,bob,success\n")
    logs = load_logs(source)
    assert len(logs) == 1
    assert logs.iloc[0]["ip_address"] == "192.0.2.10"


def test_missing_columns():
    with pytest.raises(ValueError):
        load_logs(StringIO("timestamp,username\n2026-11-23,admin\n"))


def test_summary():
    logs = make_logs([("2026-11-23 10:00:00", "192.0.2.10", "a", "failed"),
                      ("2026-11-23 10:01:00", "192.0.2.10", "a", "success")])
    result = summarize_logs(logs)
    assert result == {"total_events": 2, "failed_logins": 1, "successful_logins": 1, "unique_ips": 1}
