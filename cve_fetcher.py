"""
cve_fetcher.py
---------------
Ye module NVD (National Vulnerability Database) API se
latest CVEs (Common Vulnerabilities and Exposures) fetch karta hai.

NVD ek US government database hai jo har naye discovered
software vulnerability ko record karta hai.
"""

import requests
import time
from datetime import datetime, timedelta


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_recent_cves(api_key=None, days_back=1, results_limit=10):
    """
    Pichle 'days_back' dinon ke andar publish hui CVEs ko fetch karta hai.

    Parameters:
        api_key (str): NVD API key (optional, bina key ke bhi chalega but slow)
        days_back (int): Kitne din pehle tak ki CVEs chahiye
        results_limit (int): Maximum kitni CVEs fetch karni hain

    Returns:
        list: CVE dictionaries ki list, har ek mein id, description, cvss_score, severity
    """
    # Date range banate hain - aaj se 'days_back' din pehle tak
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days_back)

    # NVD API ko ISO format mein date chahiye
    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": results_limit,
    }

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    print(f"[*] NVD se pichle {days_back} din ki CVEs fetch kar rahe hain...")

    response = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=30)

    if response.status_code != 200:
        raise Exception(f"NVD API error: {response.status_code} - {response.text}")

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    cve_list = []
    for item in vulnerabilities:
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "Unknown")

        # Description English mein hoti hai, usko nikalte hain
        descriptions = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d["lang"] == "en"),
            "No description available"
        )

        # CVSS score nikalte hain (severity rating 0-10)
        cvss_score = None
        severity = "Unknown"
        metrics = cve_data.get("metrics", {})

        # NVD mein CVSS v3.1, v3.0, ya v2 mein se koi bhi ho sakta hai
        for metric_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if metric_version in metrics:
                metric = metrics[metric_version][0]
                cvss_data = metric.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = metric.get("baseSeverity", cvss_data.get("baseSeverity", "Unknown"))
                break

        cve_list.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": cve_data.get("published", "Unknown"),
        })

    print(f"[+] {len(cve_list)} CVEs mil gayi.")
    return cve_list


if __name__ == "__main__":
    # Test karne ke liye - direct run karke dekh sakte ho
    cves = fetch_recent_cves(days_back=2, results_limit=5)
    for cve in cves:
        print(f"\n{cve['cve_id']} | Severity: {cve['severity']} | Score: {cve['cvss_score']}")
        print(f"  {cve['description'][:150]}...")