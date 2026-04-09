#!/usr/bin/env python3
import asyncio
from pathlib import Path
from mcp.server import Server
from mcp.types import Tool, TextContent, CallToolResult
import mcp.types as types

# Import your existing modules
from generator import generate_rule as gen_rule
from validator import validate_rule
from analyzer import analyze_rule as analyze_single

# ===== CONFIGURATION – adjust to your Snort rules directory =====
SNORT_RULES_DIR = "/etc/snort/rules"   # or your actual rules dir
# ================================================================
Path(SNORT_RULES_DIR).mkdir(parents=True, exist_ok=True)

# Create server
app = Server("snort-mcp-server")

# ---------- Tool definitions ----------
@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_rules",
            description="List all Snort rules (first 20 lines per file).",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="add_rule",
            description="Add a new Snort rule to a rules file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule": {"type": "string"},
                    "filename": {"type": "string", "default": "local.rules"},
                },
                "required": ["rule"],
            },
        ),
        Tool(
            name="analyze_rules",
            description="Analyze existing rules for weaknesses.",
            inputSchema={
                "type": "object",
                "properties": {"max_rules": {"type": "integer", "default": 20}},
            },
        ),
        Tool(
            name="generate_rule",
            description="Generate a Snort rule from a threat description.",
            inputSchema={
                "type": "object",
                "properties": {"threat": {"type": "string"}},
                "required": ["threat"],
            },
        ),
        Tool(
            name="reload_snort",
            description="Reload Snort configuration (placeholder).",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="get_stats",
            description="Get Snort statistics (placeholder).",
            inputSchema={"type": "object", "properties": {}},
        ),
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "list_rules":
        rules = []
        for file in Path(SNORT_RULES_DIR).glob("*.rules"):
            try:
                with open(file) as f:
                    lines = f.readlines()
                    rules.append(f"\n--- {file.name} ---\n")
                    rules.extend(lines[:20])
            except Exception as e:
                rules.append(f"Error reading {file}: {e}\n")
        return [TextContent(type="text", text="".join(rules))]

    elif name == "add_rule":
        rule = arguments.get("rule", "")
        filename = arguments.get("filename", "local.rules")
        filepath = Path(SNORT_RULES_DIR) / filename
        try:
            with open(filepath, "a") as f:
                f.write(rule + "\n")
            return [TextContent(type="text", text=f"Rule appended to {filepath}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error: {e}")]

    elif name == "analyze_rules":
        max_rules = arguments.get("max_rules", 20)
        issues_summary = []
        count = 0
        for file in Path(SNORT_RULES_DIR).glob("*.rules"):
            try:
                with open(file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            issues = analyze_single(line)
                            if issues:
                                issues_summary.append(f"In {file.name}: {line[:80]}... -> {issues}")
                            count += 1
                            if count >= max_rules:
                                break
                if count >= max_rules:
                    break
            except Exception as e:
                issues_summary.append(f"Error reading {file}: {e}")
        if not issues_summary:
            return [TextContent(type="text", text="No issues found.")]
        return [TextContent(type="text", text="\n".join(issues_summary))]

    elif name == "generate_rule":
        threat = arguments.get("threat", "")
        if not threat:
            return [TextContent(type="text", text="Missing 'threat' argument.")]
        rule = gen_rule(threat)
        valid, msg = validate_rule(rule)
        result = f"Generated rule:\n{rule}\n\nValidation: {'✅' if valid else '❌'} {msg}"
        return [TextContent(type="text", text=result)]

    elif name == "reload_snort":
        return [TextContent(type="text", text="Reload triggered (placeholder).")]

    elif name == "get_stats":
        return [TextContent(type="text", text="Statistics: (placeholder)")]

    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    async with app.run_stdio():
        pass

if __name__ == "__main__":
    asyncio.run(main())
