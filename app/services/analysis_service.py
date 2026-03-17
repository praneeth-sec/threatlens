import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"


def analyze_cve_with_llm(cve_id, description):

    prompt = f"""
You are a cybersecurity vulnerability analysis assistant.

Analyze the following CVE from a defensive security perspective.

Return ONLY JSON in this format:

{{
"risk_level": "Critical | High | Medium | Low",
"detection_strategy": "How defenders can detect this vulnerability",
"mitigation": "How to mitigate or patch it"
}}

CVE: {cve_id}

Description:
{description}
"""

    payload = {
        "model": "llama3.1:8b",
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=120
        )

        result = response.json()["response"]

        print("AI RAW OUTPUT:")
        print(result)

        # Clean markdown formatting if present
        clean = result.replace("```json", "").replace("```", "").strip()

        start = clean.find("{")
        end = clean.rfind("}") + 1
        clean = clean[start:end]

        parsed = json.loads(clean)

        return parsed

    except Exception as e:
        print("AI ERROR:", e)

        return {
            "risk_level": "Medium",
            "detection_strategy": "Monitor logs, IDS alerts, and vulnerability scanning tools.",
            "mitigation": "Apply the latest vendor patches and restrict access to vulnerable services."
        }
