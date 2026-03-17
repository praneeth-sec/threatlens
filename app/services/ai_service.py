import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def format_ai_output(ai_text):

    sections = {
        "Mitigation Steps": [],
        "SOC Investigation Steps": [],
        "Patch / Remediation Advice": []
    }

    current_section = None

    for line in ai_text.split("\n"):

        line = line.strip()

        if not line:
            continue

        if "Mitigation Steps" in line:
            current_section = "Mitigation Steps"
            continue

        if "SOC Investigation Steps" in line:
            current_section = "SOC Investigation Steps"
            continue

        if "Patch / Remediation Advice" in line:
            current_section = "Patch / Remediation Advice"
            continue

        if line.startswith("-") and current_section:
            sections[current_section].append(line[1:].strip())

    html = ""

    if sections["Mitigation Steps"]:
        html += "<h3 class='ai-mitigation'>Mitigation Steps</h3><ul>"
        for step in sections["Mitigation Steps"]:
            html += f"<li>{step}</li>"
        html += "</ul>"

    if sections["SOC Investigation Steps"]:
        html += "<h3 class='ai-investigation'>SOC Investigation Steps</h3><ul>"
        for step in sections["SOC Investigation Steps"]:
            html += f"<li>{step}</li>"
        html += "</ul>"

    if sections["Patch / Remediation Advice"]:
        html += "<h3 class='ai-remediation'>Patch / Remediation Advice</h3><ul>"
        for step in sections["Patch / Remediation Advice"]:
            html += f"<li>{step}</li>"
        html += "</ul>"

    return html


def generate_playbook(alert):

    prompt = f"""
You are an expert SOC analyst.

Create a SOC investigation playbook for this alert:

{alert}

Include:
1. Investigation steps
2. Example Splunk queries
3. Containment actions
4. Mitigation steps
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=500
        )

        return response.choices[0].message.content

    except Exception as e:
        return f"AI playbook generation failed: {str(e)}"


def generate_mitigation(description):

    prompt = f"""
You are a senior cybersecurity SOC analyst.

Analyze the following vulnerability and produce a detailed report.

Provide AT LEAST 5 bullet points for each section.

Format exactly like this:

Mitigation Steps:
- step
- step
- step
- step
- step

SOC Investigation Steps:
- step
- step
- step
- step
- step

Patch / Remediation Advice:
- step
- step
- step
- step
- step

Rules:
- No introductions
- No explanations
- Only the three sections
- Each section must contain 5–7 bullet points

Vulnerability description:
{description}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": prompt}
            ],
            max_tokens=700
        )

        result = response.choices[0].message.content

        # cleanup
        result = result.replace("Here are the requested sections:", "")
        result = result.replace("Here are the answers:", "")

        # convert AI output into formatted HTML
        formatted_output = format_ai_output(result)

        return formatted_output

    except Exception as e:
        return f"AI mitigation generation failed: {str(e)}"
