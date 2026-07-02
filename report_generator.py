"""
report_generator.py
---------------------
Ye module final threat intelligence report banata hai
aur usko ek Markdown (.md) file mein save karta hai.
"""

from datetime import datetime


def generate_report(cve_list, analyses, daily_summary, output_path="threat_report.md"):
    """
    Saari information ko ek professional report mein combine karta hai.

    Parameters:
        cve_list (list): CVE basic info
        analyses (list): Har CVE ka AI analysis (same order mein)
        daily_summary (str): Overall daily summary
        output_path (str): Report kahan save karni hai

    Returns:
        str: Report file ka path
    """

    today = datetime.now().strftime("%d-%m-%Y")

    report_lines = [
        f"# 🛡️ Daily Threat Intelligence Report",
        f"**Date**: {today}",
        f"**Total CVEs Analyzed**: {len(cve_list)}",
        "",
        "---",
        "",
        "## 📊 Executive Summary",
        "",
        daily_summary,
        "",
        "---",
        "",
        "## 🔍 Detailed Vulnerability Analysis",
        ""
    ]

    for cve, analysis in zip(cve_list, analyses):
        report_lines.append(f"### {cve['cve_id']}")
        report_lines.append(f"- **CVSS Score**: {cve['cvss_score']}")
        report_lines.append(f"- **Severity**: {cve['severity']}")
        report_lines.append(f"- **Published**: {cve['published']}")
        report_lines.append("")
        report_lines.append(analysis)
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("")

    report_text = "\n".join(report_lines)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"[+] Report save ho gayi: {output_path}")
    return output_path