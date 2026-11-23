
"""ThreatLens Streamlit dashboard."""

# Import libraries
import pandas as pd  # Data manipulation and analysis
import plotly.express as px  # Interactive charts
import streamlit as st  # Web dashboard framework

# Import our own functions
from analytics import filter_logs, login_timeline
from detector import detect_brute_force, load_logs, summarize_logs


# 1. PAGE CONFIGURATION
st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ ThreatLens")
st.caption("Security Log Analyzer — educational rule-based prototype")


# 2. DETECTION SETTINGS & FILE UPLOAD
with st.sidebar:
    st.header("Detection Settings")

    threshold = st.slider(
        "Failed login threshold",
        min_value=2,
        max_value=20,
        value=5
    )

    window_minutes = st.slider(
        "Time window (minutes)",
        min_value=1,
        max_value=60,
        value=5
    )

    uploaded_file = st.file_uploader(
        "Upload authentication logs (CSV)",
        type=["csv"]
    )

    st.info(
        "Use synthetic or authorized, "
        "appropriately protected logs only."
    )


# 3. LOAD LOGS FIRST
try:
    logs = load_logs(
        uploaded_file
        if uploaded_file is not None
        else "data/sample_logs.csv"
    )

except (
    ValueError,
    FileNotFoundError,
    pd.errors.ParserError,
    UnicodeError
) as exc:
    st.error(f"Unable to load logs: {exc}")
    st.stop()

if logs.empty:
    st.warning("No valid log events found.")
    st.stop()


# 4. INVESTIGATION FILTERS
with st.sidebar:
    st.header("Investigation Filters")

    ip_options = sorted(
        logs["ip_address"].unique().tolist()
    )

    user_options = sorted(
        logs["username"].unique().tolist()
    )

    selected_ips = st.multiselect(
        "IP addresses (empty = all)",
        ip_options
    )

    selected_users = st.multiselect(
        "Usernames (empty = all)",
        user_options
    )

    min_day = logs["timestamp"].min().date()
    max_day = logs["timestamp"].max().date()

    date_selection = st.date_input(
        "Date range (UTC)",
        value=(min_day, max_day),
        min_value=min_day,
        max_value=max_day
    )

    if isinstance(date_selection, (tuple, list)):
        if len(date_selection) == 2:
            start_date, end_date = date_selection
        else:
            start_date = None
            end_date = None
    else:
        start_date = date_selection
        end_date = date_selection


# 5. FILTER DATA
filtered = filter_logs(
    logs,
    ips=selected_ips if selected_ips else None,
    usernames=selected_users if selected_users else None,
    start_date=start_date,
    end_date=end_date
)


# 6. DETECT SECURITY THREATS
alerts = detect_brute_force(
    filtered,
    threshold=threshold,
    window_minutes=window_minutes
)

summary = summarize_logs(filtered)


# 7. SECURITY OVERVIEW
st.subheader("Security Overview")

cols = st.columns(4)

metrics = [
    ("Total Events", summary["total_events"]),
    ("Failed Logins", summary["failed_logins"]),
    ("Unique IPs", summary["unique_ips"]),
    ("Security Alerts", len(alerts))
]

for col, (name, value) in zip(cols, metrics):
    col.metric(name, value)


# 8. LOGIN ACTIVITY TIMELINE
st.subheader("Login Activity Timeline")

if filtered.empty:
    st.info("No events match the selected filters.")
else:
    timeline = login_timeline(filtered)

    chart = px.line(
        timeline,
        x="time_bucket",
        y="events",
        color="status",
        markers=True,
        title="Login Events Over Time"
    )

    st.plotly_chart(
        chart,
        use_container_width=True
    )


# 9. LOGIN STATUS & TOP FAILED IPs
left, right = st.columns(2)

with left:
    st.subheader("Login Status")

    counts = (
        filtered["status"]
        .value_counts()
        .rename_axis("status")
        .reset_index(name="count")
    )

    if counts.empty:
        st.info("No login events to display.")
    else:
        st.plotly_chart(
            px.pie(
                counts,
                names="status",
                values="count",
                hole=0.45
            ),
            use_container_width=True
        )

with right:
    st.subheader("Top Failed Login IPs")

    counts = (
        filtered[filtered["status"] == "failed"]
        .groupby("ip_address")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values(
            "failed_attempts",
            ascending=False
        )
        .head(10)
    )

    if counts.empty:
        st.info("No failed login events.")
    else:
        st.plotly_chart(
            px.bar(
                counts,
                x="ip_address",
                y="failed_attempts"
            ),
            use_container_width=True
        )


# 10. SECURITY ALERTS
st.subheader("Detected Security Alerts")

severity_options = st.multiselect(
    "Filter alerts by severity",
    ["High", "Medium"],
    default=["High", "Medium"]
)

visible_alerts = alerts[
    alerts["severity"].isin(severity_options)
].copy()

if visible_alerts.empty:
    st.info("No alerts match the current filters.")
else:
    st.dataframe(
        visible_alerts,
        use_container_width=True,
        hide_index=True
    )

    st.download_button(
        "Download Alerts CSV",
        data=visible_alerts.to_csv(
            index=False
        ).encode("utf-8"),
        file_name="threatlens_alerts.csv",
        mime="text/csv"
    )


# 11. AUTHENTICATION EVENTS
st.subheader("Authentication Events")

statuses = st.multiselect(
    "Filter by status",
    ["failed", "success"],
    default=["failed", "success"]
)

st.dataframe(
    filtered[filtered["status"].isin(statuses)],
    use_container_width=True,
    hide_index=True
)

st.caption(
    "Alerts are heuristic and require human investigation. "
    "Risk scores are illustrative, not calibrated."
)
