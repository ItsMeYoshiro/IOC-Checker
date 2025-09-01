import os
import requests
import json

API_KEY = os.getenv("ABUSEIPDB_API_KEY")
API_URL = "https://api.abuseipdb.com/api/v2/check"

def abuseipdb_report(ip):
    if not API_KEY:
        return {"source": "AbuseIPDB", "error": "API key not set."}
    
    try:
        response = requests.get(
            API_URL,
            headers={"Key": API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}
        )
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            return {"source": "AbuseIPDB", "error": f"HTTP Status {response.status_code}", "details": response.text[:200]}

        if response.status_code != 200:
            return {"source": "AbuseIPDB", "error": data.get("errors", "Unknown error")}

        return {
            "source": "AbuseIPDB",
            "abuseConfidenceScore": data.get("data", {}).get("abuseConfidenceScore"),
            "totalReports": data.get("data", {}).get("totalReports"),
            "countryCode": data.get("data", {}).get("countryCode"),
        }
    except requests.exceptions.RequestException as e:
        return {"source": "AbuseIPDB", "error": f"Request error: {str(e)}"}