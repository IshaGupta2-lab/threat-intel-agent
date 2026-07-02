"""
virustotal_checker.py
-----------------------
Ye module VirusTotal API (FREE tier) ka use karke check karta hai
ki koi IP address, domain, ya file hash malicious hai ya nahi.

VirusTotal 70+ antivirus engines aur security vendors ka data
combine karke deta hai - "kitne engines ne isko malicious bataya".

Free tier limits: 4 requests/minute, 500 requests/day.
"""

import requests
import time


VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _make_request(endpoint, api_key):
    """Internal helper - VirusTotal ko request bhejta hai."""
    headers = {"x-apikey": api_key}
    url = f"{VT_BASE_URL}/{endpoint}"

    response = requests.get(url, headers=headers, timeout=20)

    if response.status_code == 404:
        return {"found": False}

    if response.status_code == 429:
        raise Exception("VirusTotal rate limit hit gaya (4 requests/minute free tier). Thodi der wait karo.")

    if response.status_code != 200:
        raise Exception(f"VirusTotal API error: {response.status_code} - {response.text}")

    return response.json()


def _parse_stats(data):
    """VirusTotal response se malicious/suspicious/clean stats nikalta hai."""
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    if malicious > 0:
        verdict = "🔴 DANGEROUS"
    elif suspicious > 0:
        verdict = "🟡 SUSPICIOUS"
    else:
        verdict = "🟢 CLEAN"

    return {
        "found": True,
        "verdict": verdict,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "total_engines": total,
        "reputation": attributes.get("reputation", "N/A"),
    }


def check_ip(ip_address, api_key):
    """
    Ek IP address ki reputation check karta hai.

    Parameters:
        ip_address (str): Jo IP check karni hai (e.g. "8.8.8.8")
        api_key (str): VirusTotal API key

    Returns:
        dict: Verdict aur details
    """
    data = _make_request(f"ip_addresses/{ip_address}", api_key)
    if not data.get("found", True):
        return {"found": False, "message": "Ye IP VirusTotal database mein nahi mili."}
    return _parse_stats(data)


def check_domain(domain, api_key):
    """
    Ek domain ki reputation check karta hai.

    Parameters:
        domain (str): Jo domain check karna hai (e.g. "example.com")
        api_key (str): VirusTotal API key

    Returns:
        dict: Verdict aur details
    """
    data = _make_request(f"domains/{domain}", api_key)
    if not data.get("found", True):
        return {"found": False, "message": "Ye domain VirusTotal database mein nahi mila."}
    return _parse_stats(data)


def check_file_hash(file_hash, api_key):
    """
    Ek file ki reputation check karta hai uske hash (MD5/SHA1/SHA256) se.

    Parameters:
        file_hash (str): File ka hash
        api_key (str): VirusTotal API key

    Returns:
        dict: Verdict aur details
    """
    data = _make_request(f"files/{file_hash}", api_key)
    if not data.get("found", True):
        return {"found": False, "message": "Ye file hash VirusTotal database mein nahi mila (matlab pehle kabhi scan nahi hui)."}
    return _parse_stats(data)


if __name__ == "__main__":
    # Test karne ke liye - apni API key daal kar direct run karo
    import os
    from dotenv import load_dotenv
    load_dotenv()

    key = os.getenv("VIRUSTOTAL_API_KEY")
    if key:
        result = check_ip("8.8.8.8", key)
        print(result)
    else:
        print("VIRUSTOTAL_API_KEY nahi mili .env mein")