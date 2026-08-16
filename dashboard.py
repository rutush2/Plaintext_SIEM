import time
import requests
import streamlit as st
import plotly.express as px
import pandas as pd

import config

st.set_page_config(
    page_title="Plaintext SIEM Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

SERVER_URL = f"http://{config.HOST}:{config.PORT}"

st.sidebar.title("🛡️ SIEM Control Center")
st.sidebar.markdown("---")

nav_mode = st.sidebar.radio(
    "Navigation Mode:",
    ["📊 Live Telemetry", "🔍 Forensics Investigation"],
    key="nav_mode_selection",
)
st.sidebar.markdown("---")

category_filter = "All Telemetry"
if nav_mode == "📊 Live Telemetry":
    category_filter = st.sidebar.radio(
        "Select Display Focus:",
        [
            "All Telemetry",
            "Authentication",
            "Network Flow",
            "File System",
            "Process Activity",
            "Critical Alerts",
        ],
        key="category_filter_selection",
    )
    st.sidebar.markdown("---")

st.sidebar.subheader("⚡ Live Attack Injectors")
st.sidebar.info("Trigger targeted security attack patterns directly into the ingestion stream.")

col_btn1, col_btn2 = st.sidebar.columns(2)

with col_btn1:
    if st.sidebar.button("🔥 Brute Force", key="btn_brute_force_unique", use_container_width=True):
        try:
            res = requests.post(f"{SERVER_URL}/api/attack/BRUTE_FORCE", timeout=2)
            if res.status_code == 200:
                st.sidebar.success("SSH Brute Force attack injected!")
        except Exception as e:
            st.sidebar.error(f"Failed to connect: {e}")

    if st.sidebar.button("🌐 Port Scan", key="btn_port_scan_unique", use_container_width=True):
        try:
            res = requests.post(f"{SERVER_URL}/api/attack/PORT_SCAN", timeout=2)
            if res.status_code == 200:
                st.sidebar.success("Port Scan attack injected!")
        except Exception as e:
            st.sidebar.error(f"Failed to connect: {e}")

with col_btn2:
    if st.sidebar.button("📡 Data Exfil", key="btn_data_exfil_unique", use_container_width=True):
        try:
            res = requests.post(f"{SERVER_URL}/api/attack/DATA_EXFIL", timeout=2)
            if res.status_code == 200:
                st.sidebar.success("Data Exfiltration attack injected!")
        except Exception as e:
            st.sidebar.error(f"Failed to connect: {e}")

st.title("🛡️ Plaintext SIEM Security Control Center")

st.subheader("📈 Telemetry & Threat Velocity Timeline")
try:
    timeline_res = requests.get(f"{SERVER_URL}/api/timeline", timeout=2)
    timeline_data = timeline_res.json() if timeline_res.status_code == 200 else []
    if timeline_data:
        df_tl = pd.DataFrame(timeline_data)
        fig_tl = px.line(
            df_tl,
            x="time_window",
            y="event_count",
            color="category",
            markers=True,
            labels={"time_window": "Time", "event_count": "Event Volume", "category": "Category"},
            color_discrete_sequence=px.colors.qualitative.Bold,
        )
        fig_tl.update_layout(xaxis_title="Time", yaxis_title="Events / 5s Window")
        st.plotly_chart(fig_tl, use_container_width=True)
    else:
        st.info("Awaiting streaming telemetry timeline data...")
except Exception:
    st.info("Awaiting backend server connection...")


if nav_mode == "📊 Live Telemetry":
    try:
        metrics_res = requests.get(f"{SERVER_URL}/api/metrics", timeout=2)
        metrics = metrics_res.json() if metrics_res.status_code == 200 else {}
    except Exception:
        metrics = {"total_events": 0, "malicious_events": 0, "total_alerts": 0, "total_bytes_transferred": 0}

    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    m_col1.metric("Total Events Ingested", metrics.get("total_events", 0))
    m_col2.metric("Malicious Events Flagged", metrics.get("malicious_events", 0))
    m_col3.metric("Security Alerts Triggered", metrics.get("total_alerts", 0))
    m_col4.metric("Volume Processed (MB)", round(metrics.get("total_bytes_transferred", 0) / (1024 * 1024), 2))

    st.markdown("---")

    if category_filter == "Critical Alerts":
        st.subheader("🚨 Active Security Alerts & Escalations")
        try:
            alerts_res = requests.get(f"{SERVER_URL}/api/alerts", timeout=2)
            alerts = alerts_res.json() if alerts_res.status_code == 200 else []
            if alerts:
                df_alerts = pd.DataFrame(alerts)
                st.dataframe(
                    df_alerts[
                        [
                            "timestamp",
                            "rule_name",
                            "severity",
                            "source_ip",
                            "mitre_tactic",
                            "description",
                        ]
                    ],
                    use_container_width=True,
                )
            else:
                st.info("No security alerts triggered yet. Click an attack button in the sidebar.")
        except Exception as e:
            st.error(f"Failed to fetch alerts: {e}")

    else:
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("📈 Telemetry by Event Category")
            try:
                cat_res = requests.get(f"{SERVER_URL}/api/categories", timeout=2)
                cat_data = cat_res.json() if cat_res.status_code == 200 else []
                if cat_data:
                    df_cat = pd.DataFrame(cat_data)
                    fig_cat = px.pie(
                        df_cat,
                        names="category",
                        values="count",
                        hole=0.4,
                        color_discrete_sequence=px.colors.qualitative.Set2,
                    )
                    st.plotly_chart(fig_cat, use_container_width=True)
                else:
                    st.info("Awaiting telemetry stream...")
            except Exception:
                st.info("Awaiting backend server...")

        with chart_col2:
            st.subheader("🎯 Top Threat Sources (Malicious IPs)")
            try:
                threat_res = requests.get(f"{SERVER_URL}/api/threats", timeout=2)
                threat_data = threat_res.json() if threat_res.status_code == 200 else []
                if threat_data:
                    df_threats = pd.DataFrame(threat_data)
                    fig_threats = px.bar(
                        df_threats,
                        x="source_ip",
                        y="attack_count",
                        color="max_reputation",
                        labels={"attack_count": "Event Count", "source_ip": "Source IP Address"},
                        color_continuous_scale="Reds",
                    )
                    st.plotly_chart(fig_threats, use_container_width=True)
                else:
                    st.info("No malicious threat IP sources detected in active window.")
            except Exception:
                st.info("Awaiting backend server...")

        st.markdown("---")

        st.subheader("📜 Recent Telemetry Logs")
        category_map = {
            "Authentication": "authentication",
            "Network Flow": "network",
            "File System": "file_system",
            "Process Activity": "process",
        }
        selected_cat = category_map.get(category_filter, "all")

        try:
            logs_res = requests.get(f"{SERVER_URL}/api/logs?category={selected_cat}", timeout=2)
            logs = logs_res.json() if logs_res.status_code == 200 else []
            if logs:
                st.dataframe(pd.DataFrame(logs), use_container_width=True)
            else:
                st.info("No telemetry logs match the selected filter category.")
        except Exception as e:
            st.error(f"Failed to fetch logs: {e}")

else:
    st.subheader("🔍 Incident Forensics & Blast Radius Investigation")
    st.markdown("Select an IP address to analyze its activity timeline, targeted accounts, and footprint across the network.")

    try:
        threat_res = requests.get(f"{SERVER_URL}/api/threats", timeout=2)
        threat_data = threat_res.json() if threat_res.status_code == 200 else []
        threat_ips = [item["source_ip"] for item in threat_data] if threat_data else ["185.220.101.5", "193.27.228.27"]
    except Exception:
        threat_ips = ["185.220.101.5", "193.27.228.27"]

    target_ip = st.selectbox("Select Target Source IP to Investigate:", threat_ips)

    if st.button("Run Blast Radius Query", key="btn_blast_radius_forensics", use_container_width=True):
        try:
            inv_res = requests.get(f"{SERVER_URL}/api/investigate/{target_ip}", timeout=2)
            if inv_res.status_code == 200:
                data = inv_res.json()
                summary = data.get("summary", {})
                timeline = data.get("timeline", [])

                st.markdown("---")
                st.subheader(f"📌 Forensics Summary for `{target_ip}`")

                f_col1, f_col2, f_col3, f_col4 = st.columns(4)
                f_col1.metric("Total Executed Actions", summary.get("total_actions", 0))
                f_col2.metric("Targeted Internal Hosts", summary.get("target_hosts", 0))
                f_col3.metric("Targeted System Users", summary.get("targeted_users", 0))
                f_col4.metric("Data Transferred (KB)", round(summary.get("total_bytes", 0) / 1024, 2))

                st.markdown("---")
                st.subheader("⏱️ Attack Sequence Timeline")

                if timeline:
                    df_tl = pd.DataFrame(timeline)
                    st.dataframe(
                        df_tl[
                            [
                                "timestamp",
                                "category",
                                "event_type",
                                "user_name",
                                "destination_ip",
                                "destination_port",
                                "action",
                                "status",
                            ]
                        ],
                        use_container_width=True,
                    )
                else:
                    st.warning("No records found for this IP address in current DuckDB memory buffer.")
        except Exception as e:
            st.error(f"Failed to execute forensics query: {e}")