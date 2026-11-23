"""ThreatLens Streamlit dashboard."""
import pandas as pd //Comment: This line imports the pandas library, which is used for data manipulation and analysis. It is commonly used for handling tabular data in Python.
import plotly.express as px //graph
import streamlit as st  //dashbord library
from detector import detect_brute_force, load_logs, summarize_logs

"""Make dashboard layout wide and set title and icon."""
st.set_page_config(
    page_title="ThreatLens", 
    page_icon="🛡️", 
    layout="wide")
st.title("🛡️ ThreatLens")
st.caption("Security Log Analyzer — educational rule-based prototype by minicrove")

with st.sidebar:
    st.header("Detection Settings")
    threshold = st.slider("Failed login threshold", 2, 20, 5)
    window_minutes = st.slider("Time window (minutes)", 1, 60, 5)
    uploaded_file = st.file_uploader("Upload authentication logs (CSV)", type=["csv"])
    st.info("Use synthetic or authorized, appropriately protected logs only.")
try:
    logs = load_logs(uploaded_file if uploaded_file is not None else "data/sample_logs.csv")
except (ValueError, FileNotFoundError, pd.errors.ParserError, UnicodeError) as exc:
    st.error(f"Unable to load logs: {exc}")
    st.stop()
if logs.empty:
    st.warning("No valid log events found.")
    st.stop()
alerts = detect_brute_force(logs, threshold=threshold, window_minutes=window_minutes)
summary = summarize_logs(logs)
st.subheader("Security Overview")

cols = st.columns(4)
for col, (name, value) in zip(cols, [("Total Events", summary["total_events"]),
                                    ("Failed Logins", summary["failed_logins"]),
                                    ("Unique IPs", summary["unique_ips"]),
                                    ("Security Alerts", len(alerts))]):
    col.metric(name, value)
left, right = st.columns(2)
with left:
    st.subheader("Login Status")
    counts = logs["status"].value_counts().rename_axis("status").reset_index(name="count")
    st.plotly_chart(px.pie(counts, names="status", values="count", hole=0.45), use_container_width=True)
with right:
    st.subheader("Top Failed Login IPs")
    counts = (logs[logs["status"] == "failed"].groupby("ip_address").size()
              .reset_index(name="failed_attempts").sort_values("failed_attempts", ascending=False).head(10))
    if counts.empty:
        st.info("No failed login events")
    else:
        st.plotly_chart(px.bar(counts, x="ip_address", y="failed_attempts"), use_container_width=True)
st.subheader("Detected Security Alerts")
if alerts.empty:
    st.success("No alerts matched the current detection rule.")
else:
    st.dataframe(alerts, use_container_width=True, hide_index=True)
    st.download_button("Download Alerts CSV", alerts.to_csv(index=False).encode("utf-8"),
                       file_name="threatlens_alerts.csv", mime="text/csv")
st.subheader("Authentication Events")
statuses = st.multiselect("Filter by status", ["failed", "success"], default=["failed", "success"])
st.dataframe(logs[logs["status"].isin(statuses)], use_container_width=True, hide_index=True)
st.caption("Alerts are heuristic and require human investigation. Risk scores are illustrative, not calibrated.")
