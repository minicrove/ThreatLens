"""ThreatLens authentication log parsing and detection."""
import ipaddress
from datetime import timedelta
import pandas as pd

REQUIRED_COLUMNS = ["timestamp", "ip_address", "username", "status"]


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def load_logs(source):
    df = pd.read_csv(source, dtype=str)
    missing = set(REQUIRED_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")
    df = df[REQUIRED_COLUMNS].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    for col in ("ip_address", "username", "status"):
        df[col] = df[col].fillna("").str.strip()
    df["status"] = df["status"].str.lower()
    valid = (df["timestamp"].notna() & df["ip_address"].map(is_valid_ip)
             & df["username"].ne("") & df["status"].isin(["failed", "success"]))
    return df.loc[valid].drop_duplicates().sort_values("timestamp").reset_index(drop=True)


def detect_brute_force(df, threshold=5, window_minutes=5):
    if threshold < 2 or window_minutes <= 0:
        raise ValueError("Invalid detection settings")
    alerts = []
    window = timedelta(minutes=window_minutes)
    failed = df[df["status"] == "failed"].sort_values("timestamp")
    for ip, group in failed.groupby("ip_address"):
        times = group["timestamp"].tolist()
        users = group["username"].tolist()
        left = 0
        last_alert_end = None
        for right, now in enumerate(times):
            while now - times[left] > window:
                left += 1
            count = right - left + 1
            if count < threshold:
                continue
            if last_alert_end is not None and now - last_alert_end <= window:
                last_alert_end = now
                continue
            affected_users = len(set(users[left:right + 1]))
            risk = min(100, 40 + count * 8 + affected_users * 5)
            alerts.append({
                "timestamp": now, "ip_address": ip, "failed_attempts": count,
                "affected_users": affected_users, "risk_score": risk,
                "severity": "High" if risk >= 80 else "Medium",
                "rule": "Repeated failed logins",
            })
            last_alert_end = now
    columns = ["timestamp", "ip_address", "failed_attempts", "affected_users", "risk_score", "severity", "rule"]
    return pd.DataFrame(alerts, columns=columns).sort_values("timestamp", ascending=False).reset_index(drop=True)


def summarize_logs(df):
    failed = int((df["status"] == "failed").sum())
    return {"total_events": len(df), "failed_logins": failed,
            "successful_logins": len(df) - failed, "unique_ips": df["ip_address"].nunique()}
