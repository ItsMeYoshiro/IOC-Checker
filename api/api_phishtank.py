import os
import requests
import json

API_KEY = os.getenv("PHISHTANK_API_KEY")
API_URL = "https://checkurl.phishtank.com/checkurl/"

def phishtank_report(url):
    if not API_KEY:
        return {"source": "PhishTank", "error": "API key not set."}
    
    # Adicionando o cabeçalho User-Agent
    headers = {
        'User-Agent': 'IOC-Checker-App/1.0'
    }

    try:
        payload = {
            "url": url,
            "format": "json",
            "app_key": API_KEY
        }
        # Enviando a requisição com o novo cabeçalho
        response = requests.post(API_URL, headers=headers, data=payload)

        if response.status_code != 200:
            return {"source": "PhishTank", "error": f"HTTP Status {response.status_code}", "details": response.text[:200]}

        data = response.json()
        
        if data.get("errortext"):
            return {"source": "PhishTank", "error": data["errortext"]}

        results = data.get("results", {})
        return {
            "source": "PhishTank",
            "in_database": results.get("in_database"),
            "phish": results.get("valid"),
            "verified": results.get("verified"),
            "phish_detail_url": results.get("phish_detail_page"),
        }
    except json.JSONDecodeError:
        return {"source": "PhishTank", "error": "Failed to decode JSON response.", "details": response.text[:200]}
    except requests.exceptions.RequestException as e:
        return {"source": "PhishTank", "error": str(e)}