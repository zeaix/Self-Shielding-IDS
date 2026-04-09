#!/usr/bin/env python3
import asyncio
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def main():
    server_params = StdioServerParameters(command="python", args=["mcp_server_v2.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools_result = await session.list_tools()
            tools = tools_result.tools
            print("Available tools:", [tool.name for tool in tools])

            # Test generate_rule
            result = await session.call_tool("generate_rule", {"threat": "SQL injection"})
            print("\n--- generate_rule ---\n", result.content[0].text)

            # Test list_rules
            result = await session.call_tool("list_rules", {})
            print("\n--- list_rules ---\n", result.content[0].text[:500])

if __name__ == "__main__":
    asyncio.run(main())
