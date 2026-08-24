import re, json, requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class EmailPayload(BaseModel):
    raw_email: str
    api_key: str

def trace_ip_hops(raw_headers: str):
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    found_ips = set(re.findall(ip_pattern, raw_headers))
    public_ips = [ip for ip in found_ips if not (ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.'))]
    hops = []
    for ip in public_ips[:5]:
        try:
            res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
            if res.get("status") == "success":
                hops.append({"ip": ip, "lat": res.get("lat"), "lon": res.get("lon"), "city": res.get("city"), "country": res.get("country"), "isp": res.get("isp")})
        except Exception:
            continue
    return hops

@app.get("/", response_class=HTMLResponse)
def serve_frontend():
    with open("index.html", "r") as f:
        return f.read()

@app.post("/analyze")
def analyze_email(payload: EmailPayload):
    if not payload.raw_email or not payload.api_key:
        raise HTTPException(status_code=400, detail="Missing data")
    ip_hops = trace_ip_hops(payload.raw_email)
    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={payload.api_key}"
    prompt = f'Analyze email threats (Phishing/BEC). Return JSON only: {{"threat_score": 0-100, "category": "Phishing|BEC|Malware|Clean", "urgency": true/false, "red_flags": []}}. Email: {payload.raw_email}'
    try:
        res = requests.post(gemini_url, json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=10)
        cleaned = res.json()['candidates'][0]['content']['parts'][0]['text'].replace("```json", "").replace("```", "").strip()
        ai_verdict = json.loads(cleaned)
    except Exception as e:
        ai_verdict = {"threat_score": 50, "category": "Failed", "urgency": False, "red_flags": [str(e)]}
    return {"forensics": ai_verdict, "hops": ip_hops}
