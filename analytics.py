import pandas as pd
def filter_logs(
    logs,
    ips=None,
    usernames=None,
    start_date=None,
    end_date=None
):
    result = logs.copy()

    if ips is not None:
        result = result[
            result["ip_address"].isin(ips)
        ]

    if usernames is not None:
        result = result[
            result["username"].isin(usernames)
        ]

    if start_date is not None:
        result = result[
            result["timestamp"].dt.date >= start_date
        ]

    if end_date is not None:
        result = result[
            result["timestamp"].dt.date <= end_date
        ]

    return result.copy().reset_index(drop=True)

def login_timeline(logs, frequency="h"):
    if logs.empty:
        return pd.DataFrame(
            columns=["time_bucket", "status", "events"]
        )

    grouped = (
        logs.assign(
            time_bucket=logs["timestamp"].dt.floor(frequency)
        )
        .groupby(["time_bucket", "status"], as_index=False)
        .size()
        .rename(columns={"size": "events"})
    )

    return grouped.sort_values(
        ["time_bucket", "status"]
    ).reset_index(drop=True)