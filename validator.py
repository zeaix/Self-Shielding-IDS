#!/usr/bin/env python3
"""
validator.py - Validate Snort rule syntax using simple checks.
"""

import re

def validate_rule(rule):
    """
    Check if a rule has the basic Snort structure:
    - starts with 'alert'
    - contains a msg:"..."
    - contains a sid: followed by a number
    Returns (is_valid, message).
    """
    # Trim whitespace
    rule = rule.strip()
    rule_lower = rule.lower()

    # Check 1: starts with 'alert'
    if not rule_lower.startswith('alert'):
        return False, "Rule does not start with 'alert'"

    # Check 2: contains msg:"..." (at least one double-quoted message)
    msg_pattern = r'msg:"[^"]*"'
    if not re.search(msg_pattern, rule):
        return False, "Missing msg: field with double-quoted text"

    # Check 3: contains sid: followed by a number
    sid_pattern = r'sid:\s*\d+'
    if not re.search(sid_pattern, rule_lower):
        return False, "Missing sid: field with a number"

    # Optional: check for direction arrow -> (but may appear as ->)
    if '->' not in rule:
        return False, "Missing direction arrow ->"

    # All checks passed
    return True, "Valid rule (basic structure)"

# Quick test when run directly
if __name__ == "__main__":
    good_rule = 'alert icmp any any -> any any (msg:"Ping"; sid:1000000; rev:1;)'
    bad_rule = 'alert tcp any any -> any any (msg:MissingQuotes; sid:1;)'

    print("Testing good rule:")
    v, m = validate_rule(good_rule)
    print(f"Valid: {v}, Message: {m}")

    print("\nTesting bad rule:")
    v, m = validate_rule(bad_rule)
    print(f"Valid: {v}, Message: {m}")
