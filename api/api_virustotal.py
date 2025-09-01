import os
import requests
import json
from hashlib import sha256

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY
}

def virustotal_report(ioc_value, ioc_type):
    if not API_KEY:
        return {"source": "VirusTotal", "error": "API key not set."}

    if ioc_type == "hash":
        url = f"{BASE_URL}/files/{ioc_value}"
    elif ioc_type == "domain":
        url = f"{BASE_URL}/domains/{ioc_value}"
    elif ioc_type == "ip":
        url = f"{BASE_URL}/ip_addresses/{ioc_value}"
    elif ioc_type == "url":
        hashed_url_id = sha256(ioc_value.encode()).hexdigest()
        url = f"{BASE_URL}/urls/{hashed_url_id}"
    else:
        return {"source": "VirusTotal", "error": "Unsupported IOC type."}

    try:
        resp = requests.get(url, headers=HEADERS)
        
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return {"source": "VirusTotal", "error": f"HTTP Status {resp.status_code}", "details": resp.text[:200]}

        if resp.status_code != 200:
            error_message = data.get("error", {}).get("message", "Unknown error")
            return {"source": "VirusTotal", "error": error_message}

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})

        top_engines = {}
        count = 0
        for engine, res in results.items():
            if res.get("category") == "malicious":
                top_engines[engine] = res.get("result")
                count += 1
            if count >= 5:
                break

        return {
            "source": "VirusTotal",
            "detections": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "top_engines": top_engines,
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
    except requests.exceptions.RequestException as e:
        return {"source": "VirusTotal", "error": f"Request error: {str(e)}"}

def virustotal_email_report(email):
    if not API_KEY:
        return {"source": "VirusTotal", "error": "API key not set."}
    url = f"{BASE_URL}/search"
    params = {"query": f"email:{email}"}
    try:
        resp = requests.get(url, headers=HEADERS, params=params, timeout=10)
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return {"source": "VirusTotal", "error": f"HTTP Status {resp.status_code}", "details": resp.text[:200]}
        if resp.status_code != 200:
            error_message = data.get("error", {}).get("message", "Unknown error")
            return {"source": "VirusTotal", "error": error_message}
        # O campo 'data' pode ser uma lista de recursos relacionados ao e-mail
        return {
            "source": "VirusTotal",
            "email": email,
            "related_resources": data.get("data", []),
            "context_attributes": data.get("context_attributes", {}),
        }
    except requests.exceptions.RequestException as e:
        return {"source": "VirusTotal", "error": f"Request error: {str(e)}"}