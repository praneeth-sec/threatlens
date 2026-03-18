import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def generate_ioc_analysis(ioc, malicious, total, tags):

    prompt = f"""
You are a cybersecurity threat analyst.

IOC: {ioc}
Detections: {malicious}/{total}
Tags: {tags}

Give a short professional threat analysis:
- What this IOC indicates
- Why it is risky
- What attacker behavior it suggests
- Keep it concise (4-6 lines)
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )

        return response.choices[0].message.content

    except:
        return "AI analysis unavailable."
