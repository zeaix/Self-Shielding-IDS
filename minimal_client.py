#!/usr/bin/env python3
import asyncio
from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters

async def main():
    server_params = StdioServerParameters(command="python", args=["minimal_server.py"])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Get tools result
            tools_result = await session.list_tools()
            # The result is a ListToolsResult object with a `tools` attribute
            tools = tools_result.tools
            print("Tools list type:", type(tools_result))
            print("Tools:", tools)

            # Iterate over tools
            for tool in tools:
                print(f"Tool name: {tool.name}")

            # Call hello tool
            result = await session.call_tool("hello", {})
            print("Response:", result.content[0].text)

if __name__ == "__main__":
    asyncio.run(main())
