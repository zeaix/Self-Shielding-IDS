import streamlit as st
import asyncio
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def call_tool(tool, args):
    server_params = StdioServerParameters(command="python", args=["mcp_server_v2.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool, args)
            return result.content[0].text

st.set_page_config(page_title="Snort MCP Controller", layout="wide")
st.title("🛡️ Self-Shielding IDS v2 – MCP Control Panel")

col1, col2 = st.columns(2)

with col1:
    st.header("Rule Management")
    if st.button("📋 List Rules"):
        with st.spinner("Fetching rules..."):
            result = asyncio.run(call_tool("list_rules", {}))
            st.text_area("Rules (first 20 lines per file)", result, height=300)

    st.subheader("Add New Rule")
    new_rule = st.text_area("Rule text", height=150)
    if st.button("➕ Add Rule"):
        if new_rule.strip():
            with st.spinner("Adding..."):
                result = asyncio.run(call_tool("add_rule", {"rule": new_rule}))
                st.success(result)
        else:
            st.warning("Please enter a rule.")

    st.subheader("Generate Rule from Threat")
    threat = st.text_input("Threat description")
    if st.button("✨ Generate"):
        if threat.strip():
            with st.spinner("Generating..."):
                result = asyncio.run(call_tool("generate_rule", {"threat": threat}))
                st.text_area("Generated Rule & Validation", result, height=150)
        else:
            st.warning("Enter a threat description.")

with col2:
    st.header("AI‑Based Full Analysis")
    if st.button("🤖 Analyze ALL Rules with AI"):
        with st.spinner("AI is analyzing all rules (this may take a while)..."):
            result = asyncio.run(call_tool("analyze_all_rules_ai", {"max_rules": 50}))
            st.text_area("AI Analysis Report", result, height=500)
    st.subheader("AI‑Based Rule Improvement")
    max_rules_to_improve = st.slider("Max rules to improve", 1, 100, 20)
    if st.button("✨ Improve Rules (modifies original files)"):
        with st.spinner("AI is improving rules (this may take a while)..."):
            result = asyncio.run(call_tool("improve_rules_ai", {"max_rules": max_rules_to_improve}))
            st.text_area("Improvement Report", result, height=500)
