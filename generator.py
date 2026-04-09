#!/usr/bin/env python3
"""
generator.py - Generate Snort rules using Groq LLM.
"""

import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
client = Groq(api_key=os.getenv("groq_api_key"))

def generate_rule(threat_description):
    prompt = f"""You are an expert Snort rule writer. Convert the following threat description into a single valid Snort rule.

Threat: {threat_description}

Rules for the output:
- Output ONLY the rule text, no explanations.
- Use Snort 3 syntax.
- The rule must start with 'alert'.
- Include a descriptive 'msg' field.
- Include a 'sid' between 1000000 and 1000100.
- Use standard variables like $HOME_NET, $EXTERNAL_NET, $HTTP_SERVERS, $HTTP_PORTS.

Here are examples of good conversions:

Threat: SQL injection attempt via URL parameter
Output: alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS ( msg:"SQL Injection Attempt"; content:"union"; http_uri; sid:1000001; rev:1; )

Threat: Log4j JNDI exploit attempt
Output: alert tcp $EXTERNAL_NET any -> $HOME_NET any ( msg:"Log4j JNDI Exploit"; content:"jndi:"; nocase; sid:1000002; rev:1; )

Threat: SSH brute force attack
Output: alert tcp $EXTERNAL_NET any -> $HOME_NET 22 ( msg:"SSH Brute Force"; flow:to_server,established; content:"SSH-"; depth:7; detection_filter:track_by_src,count 5,seconds 60; sid:1000003; rev:1; )

Now generate the Snort rule for this threat: {threat_description}
"""
    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="llama-3.3-70b-versatile",
            temperature=0.2,
            max_tokens=500
        )
        rule = response.choices[0].message.content.strip()
        return rule
    except Exception as e:
        return f"ERROR: {str(e)}"

if __name__ == "__main__":
    threat = "Apache Log4j JNDI exploit"
    rule = generate_rule(threat)
    print("Generated rule:\n", rule)
