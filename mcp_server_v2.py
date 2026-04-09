#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# existing modules
from validator import validate_rule
from analyzer import analyze_rule as analyze_single, analyze_rule_with_ai
import sys
import shutil
from datetime import datetime
print("DEBUG: analyze_rule_with_ai imported as:", analyze_rule_with_ai, file=sys.stderr)

# Snort rules directory
SNORT_RULES_DIR = "/home/zeaix/snort_test_rules"
#SNORT_RULES_DIR = "/etc/snort/rules"
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
        Tool(
            name="analyze_rule_ai",
            description="Use AI to analyze a Snort rule for weaknesses and improvements.",
            inputSchema={
                "type": "object",
                "properties": {
                    "rule": {"type": "string", "description": "Snort rule to analyze"},
                },
                "required": ["rule"],
            },
        ),
        Tool(
            name="analyze_all_rules_ai",
            description="Analyze ALL Snort rules in the directory using AI and return a summary of weaknesses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_rules": {"type": "integer", "description": "Maximum number of rules to analyze (default: 20)"},
                },
            },
        ),
        Tool(
            name="improve_rules_ai",
            description="Analyze each rule, generate an improved version, and update the original file by commenting out the old rule and adding the improved rule below it. Creates a backup (.bak) of each modified file.",
            inputSchema={
                "type": "object",
                "properties": {
                    "max_rules": {"type": "integer", "description": "Maximum number of rules to improve (default: 20)"},
                },
            },
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
        from generator import generate_rule as gen_rule
        from validator import validate_rule
        threat = arguments.get("threat", "")
        if not threat:
            return [TextContent(type="text", text="Missing 'threat' argument.")]
        rule = gen_rule(threat)
        valid, msg = validate_rule(rule)
        result = f"Generated rule:\n{rule}\n\nValidation: {'✅' if valid else '❌'} {msg}"
        return [TextContent(type="text", text=result)]
    elif name == "reload_snort":
        # Placeholder – implement real reload if needed
        return [TextContent(type="text", text="Reload triggered (placeholder).")]

    elif name == "get_stats":
        return [TextContent(type="text", text="Statistics: (placeholder)")]
    elif name == "analyze_all_rules_ai":
        import sys
        from analyzer import analyze_rule_with_ai   # import locally to ensure it's in scope
        print("DEBUG: In handler, analyze_rule_with_ai is", analyze_rule_with_ai, file=sys.stderr)
        max_rules = arguments.get("max_rules", 5)
        print(f"DEBUG: max_rules = {max_rules}", file=sys.stderr)
        issues_summary = []
        count = 0
        rule_files = list(Path(SNORT_RULES_DIR).glob("*.rules"))
        print(f"DEBUG: Found {len(rule_files)} rule files in {SNORT_RULES_DIR}", file=sys.stderr)
        for file in rule_files:
            print(f"DEBUG: Reading {file}", file=sys.stderr)
            try:
                with open(file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            print(f"DEBUG: Processing rule: {line[:80]}", file=sys.stderr)
                        # call AI function
                            result = analyze_rule_with_ai(line)
                            issues_summary.append(f"\n--- In {file.name} ---\nRule: {line[:100]}...\nAI Analysis:\n{result}\n")
                            count += 1
                            if count >= max_rules:
                                break
                if count >= max_rules:
                    break
            except Exception as e:
                print(f"DEBUG: Error reading {file}: {e}", file=sys.stderr)
                issues_summary.append(f"Error reading {file}: {e}")
        if not issues_summary:
             return [TextContent(type="text", text="No rules found or none analyzed.")]
        full_report = "\n".join(issues_summary)
        return [TextContent(type="text", text=full_report[:5000])]
    elif name == "improve_rules_ai":
        import sys
        # Force local import to ensure function is in scope
        from analyzer import analyze_rule_with_ai
        from generator import generate_rule as gen_rule
        from validator import validate_rule
        import shutil
        from datetime import datetime
        from groq import Groq
        import os
        from dotenv import load_dotenv

        print("DEBUG: improve_rules_ai handler started", file=sys.stderr)
        print(f"DEBUG: analyze_rule_with_ai = {analyze_rule_with_ai}", file=sys.stderr)

        max_rules = arguments.get("max_rules", 20)
        rules_processed = 0
        report_lines = []
        changed_files = []
        rule_files = list(Path(SNORT_RULES_DIR).glob("*.rules"))
        print(f"DEBUG: Found {len(rule_files)} rule files", file=sys.stderr)

        for file in rule_files:
            if rules_processed >= max_rules:
                break

            # Create timestamped backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = file.with_suffix(f".{timestamp}.bak")
            shutil.copy2(file, backup_path)
            print(f"DEBUG: Backed up {file} to {backup_path}", file=sys.stderr)

            original_lines = []
            with open(file) as f:
                original_lines = f.readlines()

            new_lines = []
            file_changed = False

            for line in original_lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and rules_processed < max_rules:
                    rules_processed += 1
                    print(f"DEBUG: Processing rule from {file.name}: {stripped[:80]}", file=sys.stderr)

                    # Analyze rule using AI
                    analysis = analyze_rule_with_ai(stripped)

                    # Build prompt for improved rule
                    improvement_prompt = f"""The following Snort rule has weaknesses:
{analysis}

Please generate an improved version of this Snort rule that addresses the weaknesses. Output ONLY the new rule text, nothing else.

Original rule: {stripped}
Improved rule:"""

                    # Call Groq  API key should be replaced from this file and analyzer, generator
                    load_dotenv()
                    client = Groq(api_key=os.getenv("grok_api_key"))
                    response = client.chat.completions.create(
                        messages=[{"role": "user", "content": improvement_prompt}],
                        model="llama-3.3-70b-versatile",
                        temperature=0.3,
                        max_tokens=500
                    )
                    improved_rule = response.choices[0].message.content.strip()

                    # Validate improved rule
                    valid, msg = validate_rule(improved_rule)
                    if valid:
                        # Comment out original and add improved below
                        new_lines.append("# [Self-Shielding IDS] Commented out original rule:\n")
                        new_lines.append("# " + line)
                        new_lines.append(improved_rule + "\n")
                        report_lines.append(f"✅ Updated {file.name}:\n  Original: {stripped}\n  Improved: {improved_rule}\n")
                        file_changed = True
                    else:
                        # Keep original
                        new_lines.append(line)
                        report_lines.append(f"❌ Failed to generate valid improvement for {file.name}:\n  Original: {stripped}\n  Generated: {improved_rule}\n  Validation: {msg}\n")
                else:
                    new_lines.append(line)

            if file_changed:
                with open(file, 'w') as f:
                    f.writelines(new_lines)
                changed_files.append(str(file))
                report_lines.append(f"File {file.name} updated (backup at {backup_path}).\n")
            else:
                backup_path.unlink()

        if not report_lines:
            return [TextContent(type="text", text="No rules processed.")]
        full_report = "\n".join(report_lines)
        if changed_files:
            full_report += f"\n\nFiles modified:\n" + "\n".join(changed_files)
        return [TextContent(type="text", text=full_report[:5000])]
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )

if __name__ == "__main__":
    asyncio.run(main())
