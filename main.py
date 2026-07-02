"""
main.py
--------
Ye main script hai jo poore Threat Intelligence Agent ko chalata hai.

Flow:
1. NVD API se latest CVEs fetch karo
2. Har CVE ko Gemini AI se analyze karwao
3. Overall daily summary banwao
4. Sab ko combine karke ek report file mein save karo
"""

import os
from dotenv import load_dotenv
import google.generativeai as genai

from cve_fetcher import fetch_recent_cves
from ai_analyst import analyze_cve, generate_daily_summary
from report_generator import generate_report


def main():
    # .env file se API keys load karte hain
    load_dotenv()

    gemini_api_key = os.getenv("GEMINI_API_KEY")
    nvd_api_key = os.getenv("NVD_API_KEY") or None

    if not gemini_api_key:
        print("[!] ERROR: GEMINI_API_KEY nahi mili. .env file check karo.")
        return

    # Gemini model banate hain
    genai.configure(api_key=gemini_api_key)
    model = genai.GenerativeModel("gemini-2.5-flash")

    # Step 1: Latest CVEs fetch karo
    print("=" * 60)
    print("STEP 1: Latest vulnerabilities fetch kar rahe hain...")
    print("=" * 60)
    cve_list = fetch_recent_cves(api_key=nvd_api_key, days_back=2, results_limit=5)

    if not cve_list:
        print("[!] Koi CVE nahi mili is date range mein. Days_back badha kar try karo.")
        return

    # Step 2: Har CVE ko AI se analyze karwao
    print("\n" + "=" * 60)
    print("STEP 2: AI se har vulnerability analyze karwa rahe hain...")
    print("=" * 60)
    analyses = []
    for i, cve in enumerate(cve_list, 1):
        print(f"[*] ({i}/{len(cve_list)}) Analyzing {cve['cve_id']}...")
        analysis = analyze_cve(model, cve)
        analyses.append(analysis)

    # Step 3: Overall daily summary banwao
    print("\n" + "=" * 60)
    print("STEP 3: Overall daily summary generate kar rahe hain...")
    print("=" * 60)
    daily_summary = generate_daily_summary(model, cve_list)

    # Step 4: Final report banao
    print("\n" + "=" * 60)
    print("STEP 4: Final report generate kar rahe hain...")
    print("=" * 60)
    report_path = generate_report(cve_list, analyses, daily_summary)

    print("\n[✅] Poora process complete ho gaya!")
    print(f"[✅] Report yahan hai: {report_path}")


if __name__ == "__main__":
    main()