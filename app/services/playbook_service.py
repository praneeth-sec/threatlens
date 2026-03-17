import google.generativeai as genai

def generate_playbook(alert):

    prompt = f"""
You are a SOC analyst.

Create an investigation playbook for the alert:

{alert}

Include:
- Investigation steps
- Splunk queries
- Containment steps
"""

    response = model.generate_content(prompt)

    return response.text
