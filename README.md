# 🛡️ AI Threat Hunting & Threat Intelligence Agent

Ek autonomous AI agent jo latest cybersecurity vulnerabilities (CVEs) ko
track karta hai, unka AI-powered analysis karta hai (Google Gemini — FREE),
aur ek daily threat report generate karta hai.

## 🌐 Live Demo

**App yahan live hai**: https://threat-intel-agent-mefegbwaradqyz4apu7bz3.streamlit.app/

## 📁 Project Files

```
threat_intel_agent/
├── main.py              # Terminal version - chalao aur report file milegi
├── app.py               # Browser dashboard version
├── cve_fetcher.py        # NVD API se CVEs fetch karta hai
├── ai_analyst.py         # Gemini AI se analysis karwata hai
├── virustotal_checker.py # IP/domain/file reputation check karta hai
├── report_generator.py   # Terminal version ke liye report banata hai
├── requirements.txt      # Zaroori Python libraries
├── .env.example           # API key ka template
└── README.md
```

---

## 🚀 STEP-BY-STEP SETUP (Bilkul shuru se)

### ✅ Step 1: Python check karo

Terminal/Command Prompt kholo, type karo:

```
python --version
```

Version number dikhna chahiye (jaise `Python 3.11.5`). Agar error aaye,
`python3 --version` try karo. Kuch bhi na chale toh https://python.org
se install karo pehle.

### ✅ Step 2: Project folder mein jao

Jahan saari files hain (download ki hui), wahan terminal se jao:

```
cd path/to/threat_intel_agent
```

Files check karo:
- Windows: `dir`
- Mac/Linux: `ls`

`main.py`, `app.py`, `cve_fetcher.py` waghera dikhne chahiye.

### ✅ Step 3: Libraries install karo

```
pip install -r requirements.txt
```

Agar `pip` na chale, `pip3` try karo. 1-2 minute lagega.

### ✅ Step 4: FREE Gemini API key lo

**Ye bilkul free hai, koi credit/debit card nahi chahiye.**

1. Jao: https://aistudio.google.com/apikey
2. Google account se login karo
3. "Create API key" button dabao
4. Jo key dikhe, usko copy kar lo (kuch is tarah dikhegi: `AIzaSy...`)

### ✅ Step 4.5: FREE VirusTotal API key lo (optional, IP/domain check ke liye)

1. Jao: https://www.virustotal.com/gui/join-us
2. Free account banao (email se signup)
3. Login karne ke baad, apni profile pe jao → "API Key" section
4. Key copy kar lo

### ✅ Step 5: `.env` file banao

`.env.example` file ka copy banao naam `.env` ke saath:

- Windows: `copy .env.example .env`
- Mac/Linux: `cp .env.example .env`

Ab `.env` file ko Notepad/VS Code mein kholo, aur ye line:

```
GEMINI_API_KEY=your_gemini_api_key_here
```

Isko apni asli key se replace karo:

```
GEMINI_API_KEY=AIzaSyxxxxxxxxxxxxxxxxxxxxx
VIRUSTOTAL_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

Save karo, file band karo.

### ✅ Step 6: Chalao! 🎉

Do options hain:

**Option A — Terminal mein (Report file banegi):**

```
python main.py
```

Progress terminal mein dikhega. End mein `threat_report.md` file
banegi same folder mein — usko kholo dekhne ke liye.

**Option B — Browser dashboard (recommended, dekhne mein achha):**

```
streamlit run app.py
```

Browser automatically khul jayega. "Scan chalao" button dabao.

---

## ⚠️ Common Errors aur Solutions

| Error | Solution |
|---|---|
| `python: command not found` | `python3` use karo instead of `python` |
| `pip: command not found` | `pip3` use karo |
| `ModuleNotFoundError: No module named 'google'` | Step 3 phir se chalao |
| `GEMINI_API_KEY nahi mili` | `.env` file check karo — sahi folder mein hai, key sahi paste hui hai (extra space na ho) |
| `429 ResourceExhausted` error | Gemini free tier ka daily/per-minute limit hit hua hai, kuch minute wait karo |
| Streamlit browser mein nahi khula | Manually `http://localhost:8501` type karo browser mein |

---

## 💡 Gemini Free Tier Ki Limits

Gemini API bilkul free hai lekin har din ek limit hai kitni requests bhej sakte ho
(ek personal/learning project ke liye ye limit kaafi zyada hai). Agar limit hit ho
jaye, thodi der wait karo ya kal try karo.

---

## 🎯 Future Improvements (Aage add kar sakte ho)

- VirusTotal API add karke malware indicators check karna
- Shodan API add karke exposed devices dhundna
- Daily automatic run ke liye scheduler setup karna
- Email/Slack notification jab critical CVE mile