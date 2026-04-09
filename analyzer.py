#!/usr/bin/env python3
"""
analyzer.py - Detect vulnerabilities in Snort rules (heuristic + AI).
"""

import os
import re
from groq import Groq
from dotenv import load_dotenv

# ========== Heuristic Rule Analysis ==========
def analyze_rule(rule):
    issues = []
    rule_lower = rule.lower()
    if re.search(r'any\s+any\s+->\s+any\s+any', rule_lower):
        issues.append("HIGH: Rule matches ALL traffic.")
    if 'content:' in rule_lower and 'nocase' not in rule_lower:
        issues.append("MEDIUM: Content match is case-sensitive.")
    if 'msg:' not in rule:
        issues.append("LOW: No 'msg' field.")
    if 'content:' not in rule_lower and 'pcre:' not in rule_lower:
        issues.append("HIGH: No payload signature.")
    if 'uricontent:' in rule_lower:
        issues.append("MEDIUM: Deprecated 'uricontent'.")
    return issues

# ========== AI-Based Rule Analysis ==========
load_dotenv()
client = Groq(api_key=os.getenv("groq_api_key"))

def analyze_rule_with_ai(rule_text):
    prompt = f"""You are a cybersecurity expert. Analyze the following Snort rule and identify weaknesses, potential false positives/negatives, and suggest improvements.

Rule: {rule_text}

Provide concise bullet points focusing on:
- Syntax errors
- Over‑broad matching
- Missing case‑insensitive flags
- Lack of signature content
- Any other security issues

If the rule is good, say "No issues found."
"""
    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            temperature=0.3,
            max_tokens=500
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error during AI analysis: {e}"
