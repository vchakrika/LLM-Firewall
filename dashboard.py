"""Streamlit telemetry dashboard. Run: streamlit run dashboard.py
(Renamed from app.py so it no longer clashes with the `app/` package.)
"""
import sqlite3

import pandas as pd
import plotly.express as px
import streamlit as st

from app.config import DB_PATH

st.set_page_config(page_title="LLM Security Gateway Monitor", layout="wide")
st.title("🛡️ LLM Security Gateway — Telemetry Dashboard")


def load_data() -> pd.DataFrame:
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM telemetry ORDER BY id DESC", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


df = load_data()

if not df.empty:
    total = len(df)
    blocked = len(df[df["status"].str.startswith("BLOCKED")])

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", total)
    c2.metric("Attacks Blocked", blocked)
    c3.metric("Block Rate", f"{blocked / total * 100:.1f}%")
    c4.metric("p95 Latency", f"{df['latency_ms'].quantile(0.95):.1f} ms")

    st.divider()
    left, right = st.columns([1, 2])
    with left:
        st.subheader("Traffic Status")
        st.plotly_chart(
            px.pie(
                df, names="status", hole=0.4, color="status",
                color_discrete_map={
                    "PASSED": "#2ecc71", "BLOCKED_INPUT": "#e74c3c",
                    "BLOCKED_OUTPUT": "#e67e22", "UPSTREAM_ERROR": "#95a5a6",
                },
            ),
            use_container_width=True,
        )
    with right:
        st.subheader("Latency per request (ms)")
        st.plotly_chart(px.line(df.iloc[::-1], x="id", y="latency_ms", markers=True),
                        use_container_width=True)

    st.subheader("Event Log")
    st.dataframe(df[["id", "timestamp", "status", "reason", "latency_ms", "prompt_snippet"]],
                 use_container_width=True)
else:
    st.info("No telemetry yet. Send some requests (e.g. run evaluate.py) to populate it.")

if st.button("Refresh"):
    st.rerun()
