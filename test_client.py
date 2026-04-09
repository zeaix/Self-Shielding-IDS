import asyncio
from mcp.client.stdio import stdio_client
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters

async def main():
    server_params = StdioServerParameters(command="python", args=["mcp_server.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print("Available tools:", [tool.name for tool in tools])

            # Test generate_rule
            result = await session.call_tool("generate_rule", {"threat": "SQL injection"})
            print("\n--- generate_rule ---\n", result.content[0].text)

            # Test list_rules
            result = await session.call_tool("list_rules", {})
            print("\n--- list_rules ---\n", result.content[0].text[:500])

if __name__ == "__main__":
    asyncio.run(main())
