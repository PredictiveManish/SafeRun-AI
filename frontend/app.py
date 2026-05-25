"""
Streamlit frontend for SafeRun AI.
Provides code editor, scan/execute buttons, and history viewer.
"""

import streamlit as st
import requests
import json
from datetime import datetime

# Configuration
BACKEND_URL = "http://localhost:8000"

st.set_page_config(
    page_title="SafeRun AI - Secure Code Sandbox",
    page_icon=None,
    layout="wide",
)

# Sidebar
with st.sidebar:
    st.image(
        "https://via.placeholder.com/150x50?text=SafeRun+AI", use_column_width=True
    )  # placeholder
    st.markdown("## SafeRun AI")
    st.markdown("**Secure sandbox execution for AI-generated code**")
    st.markdown("---")
    st.markdown("### Active Policy")
    try:
        policy_resp = requests.get(f"{BACKEND_URL}/health", timeout=2)
        if policy_resp.status_code == 200:
            st.success("Backend connected")
        else:
            st.error("Backend unreachable")
    except:
        st.error("Backend not running")
    st.markdown(
        "Default policy: **restrictive** (no network, no writes, limited resources)"
    )
    st.markdown("---")
    st.markdown("### Safety Controls")
    st.markdown("- AST scanner")
    st.markdown("- Docker sandbox")
    st.markdown("- Non-root user")
    st.markdown("- Read-only FS")
    st.markdown("- Resource limits")
    st.markdown("---")
    st.markdown(
        "[GitHub](https://github.com/predictivemanish/saferun-ai) | [Report Issue](https://github.com/predictivemanish/saferun-ai/issues)"
    )

# Main area
st.title("SafeRun AI")
st.subheader("Run AI-generated Python code in a secure sandbox")

# Code editor
code_default = """# Example safe code
def fibonacci(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

print(f"fib(10) = {fibonacci(10)}")
"""

code = st.text_area("Paste your Python code here:", value=code_default, height=300)

col1, col2 = st.columns(2)
with col1:
    scan_btn = st.button("Scan Only", type="secondary", use_container_width=True)
with col2:
    execute_btn = st.button(
        "Execute in Sandbox", type="primary", use_container_width=True
    )

# Output panels
st.markdown("---")
st.subheader("Results")

if scan_btn:
    with st.spinner("Scanning code..."):
        try:
            resp = requests.post(f"{BACKEND_URL}/scan", json={"code": code}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                col_risk, col_block = st.columns(2)
                with col_risk:
                    risk = data.get("risk_level", "UNKNOWN")
                    if risk == "LOW":
                        st.success(f"Risk Level: {risk}")
                    elif risk == "MEDIUM":
                        st.warning(f"Risk Level: {risk}")
                    elif risk == "HIGH":
                        st.error(f"Risk Level: {risk}")
                    else:
                        st.error(f"Risk Level: {risk} (BLOCKED)")
                with col_block:
                    blocked = data.get("blocked", False)
                    if blocked:
                        st.error("Blocked by policy")
                    else:
                        st.success("Not blocked")

                st.markdown("**Warnings:**")
                for w in data.get("warnings", []):
                    st.warning(w)

                st.markdown("**Detected Patterns:**")
                st.code(", ".join(data.get("detected_patterns", [])), language="text")

                st.markdown("**Policy Violations:**")
                for v in data.get("policy_violations", []):
                    st.error(v)

                st.markdown("**Explanation:**")
                st.info(data.get("explanation", "No explanation generated."))
            else:
                st.error(f"Scan failed: HTTP {resp.status_code}")
        except Exception as e:
            st.error(f"Error: {e}")

if execute_btn:
    override = st.checkbox(
        "Override safety blocks? (Only if you trust the code)", value=False
    )
    with st.spinner("Executing in sandbox..."):
        try:
            resp = requests.post(
                f"{BACKEND_URL}/execute",
                json={"code": code, "override": override},
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                st.success(f"Execution Status: {data.get('status', 'unknown').upper()}")
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Risk Level", data.get("risk_level", "N/A"))
                with col2:
                    st.metric("Execution Time", f"{data.get('execution_time', 0):.3f}s")
                if data.get("blocked"):
                    st.error("Code was blocked from execution (overridden or policy).")
                st.markdown("**Stdout:**")
                st.code(data.get("stdout", ""), language="text")
                st.markdown("**Stderr:**")
                st.code(data.get("stderr", ""), language="text")
                if data.get("warnings"):
                    st.markdown("**Warnings:**")
                    for w in data["warnings"]:
                        st.warning(w)
                st.markdown("**Explanation:**")
                st.info(data.get("explanation", "No explanation."))
            else:
                st.error(f"Execution failed: HTTP {resp.status_code} - {resp.text}")
        except Exception as e:
            st.error(f"Error: {e}")

# History section (replace the existing history part)
st.markdown("---")
st.subheader("📜 Execution History")
if st.button("Refresh History"):
    st.rerun()

try:
    hist_resp = requests.get(f"{BACKEND_URL}/history", timeout=5)
    if hist_resp.status_code == 200:
        history = hist_resp.json()
        if history:
            for record in history[:10]:
                with st.expander(
                    f"ID {record['id']} - {record['created_at']} - {record['status']} - Risk: {record['risk_level']}"
                ):
                    st.write(f"**Code hash:** {record['code_hash'][:16]}...")
                    st.write(f"**Blocked:** {record['blocked']}")
                    st.write(f"**Exit code:** {record['exit_code']}")
                    st.write(f"**Execution time:** {record['execution_time']:.3f}s")
                    # Unique keys for each text_area
                    st.text_area(
                        "Stdout (first 500 chars)",
                        record["stdout"][:500],
                        height=100,
                        key=f"stdout_{record['id']}",
                    )
                    if record["stderr"]:
                        st.text_area(
                            "Stderr (first 500 chars)",
                            record["stderr"][:500],
                            height=100,
                            key=f"stderr_{record['id']}",
                        )
        else:
            st.info("No execution history yet.")
    else:
        st.warning("Could not fetch history.")
except Exception as e:
    st.warning(f"History unavailable: {e}")

st.markdown("---")
st.caption(
    "Security Disclaimer: This sandbox provides layered security but is not perfect. Do not run untrusted code from unknown sources without review."
)
