import requests
import json

API_URL = "https://otx.alienvault.com/api/v1/indicators"

def alienvault_report(ioc_type, value):
    try:
        url = f"{API_URL}/{ioc_type}/{value}/general"
        response = requests.get(url)

        if response.status_code != 200:
            return {"source": "AlienVault", "error": f"HTTP Status {response.status_code}", "details": response.text[:200]}

        data = response.json()
        
        pulse_info = data.get("pulse_info", {})
        return {
            "source": "AlienVault",
            "pulse_count": pulse_info.get("count"),
            "tags": pulse_info.get("tags"),
            "references": data.get("references"),
        }
    except json.JSONDecodeError:
        return {"source": "AlienVault", "error": "Failed to decode JSON response.", "details": response.text[:200]}
    except requests.exceptions.RequestException as e:
        return {"source": "AlienVault", "error": f"Request error: {str(e)}"}