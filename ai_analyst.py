"""
ai_analyst.py (GROQ VERSION)
--------------
Ye module Groq AI (FREE, fast) ka use karke raw CVE data ko
samajhne layak (human-readable) analysis mein convert karta hai.

Groq free tier Gemini se zyada generous hai (~30 requests/minute,
1000+ requests/day depending on model), aur bahut fast bhi hai.

Saari CVEs ek hi API call mein batch analyze hoti hain taaki
requests kam se kam lagein.
"""

import time
import json
import re
from groq import Groq, RateLimitError


def _call_groq_with_retry(client, prompt, model="llama-3.3-70b-versatile", max_retries=5, base_delay=10):
    for attempt in range(1, max_retries + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.4,
            )
            return response.choices[0].message.content
        except RateLimitError:
            if attempt == max_retries:
                raise
            wait_time = base_delay * attempt
            print(f"[WARN] Rate limit hit (attempt {attempt}/{max_retries}). Waiting {wait_time}s...")
            time.sleep(wait_time)
    raise RuntimeError("Groq API call failed after all retries.")


def analyze_cves_batch(client, cve_list):
    """
    SAARI CVEs ko ek hi API call mein analyze karta hai.

    Parameters:
        client: Groq client object
        cve_list (list): CVEs ki list

    Returns:
        dict: { cve_id: analysis_text } mapping
    """

    cve_block = "\n\n".join([
        f"CVE ID: {cve['cve_id']}\n"
        f"CVSS Score: {cve['cvss_score']}\n"
        f"Severity: {cve['severity']}\n"
        f"Description: {cve['description']}"
        for cve in cve_list
    ])

    prompt = f"""Tum ek experienced cybersecurity threat analyst ho. Neeche multiple CVEs ki details di gayi hain. Har CVE ko alag-alag analyze karo.

{cve_block}

Apna response STRICTLY is JSON format mein do, kuch aur text mat likho (na preamble, na markdown backticks):

{{
  "CVE_ID_1": {{
    "summary": "2-3 lines simple language mein",
    "exploitation_risk": "kitni easily exploit ho sakti hai",
    "detection_methods": "kaise detect karein",
    "mitigation": "kya steps lene chahiye"
  }},
  "CVE_ID_2": {{ ... }}
}}

Har CVE ke liye uska actual CVE ID key ke roop mein use karo."""

    raw_text = _call_groq_with_retry(client, prompt)

    cleaned = re.sub(r"```json|```", "", raw_text).strip()

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return {cve["cve_id"]: raw_text for cve in cve_list}

    results = {}
    for cve in cve_list:
        cve_id = cve["cve_id"]
        entry = data.get(cve_id)
        if entry:
            results[cve_id] = (
                f"**Summary**: {entry.get('summary', 'N/A')}\n\n"
                f"**Exploitation Risk**: {entry.get('exploitation_risk', 'N/A')}\n\n"
                f"**Detection Methods**: {entry.get('detection_methods', 'N/A')}\n\n"
                f"**Mitigation Recommendations**: {entry.get('mitigation', 'N/A')}"
            )
        else:
            results[cve_id] = "Analysis not available (parsing issue)."

    return results


def generate_daily_summary(client, cve_list):
    cve_summaries = "\n\n".join([
        f"- {cve['cve_id']} (Severity: {cve['severity']}, Score: {cve['cvss_score']})"
        for cve in cve_list
    ])

    prompt = f"""Tum ek senior threat intelligence analyst ho. Neeche aaj ki discovered vulnerabilities ki list hai. Ek short executive summary likho jo security team ko diya jaayega.

Aaj ki CVEs:
{cve_summaries}

Summary mein ye batao:
1. Overall risk level (Low/Medium/High/Critical) aaj ke liye
2. Sabse dangerous 1-2 vulnerabilities kaunsi hain aur kyun
3. Security team ko sabse pehle kya priority se dekhna chahiye

Response short aur to-the-point rakho, 150 words se zyada nahi."""

    return _call_groq_with_retry(client, prompt)