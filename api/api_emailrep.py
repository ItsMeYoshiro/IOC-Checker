import requests

def emailrep_report(email):
    url = f"https://emailrep.io/{email}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return {"source": "EmailRep", "error": f"HTTP {response.status_code}", "details": response.text[:200]}
        data = response.json()
        return {
            "source": "EmailRep",
            "email": email,
            "reputation": data.get("reputation"),
            "suspicious": data.get("suspicious"),
            "references": data.get("references"),
            "details": data.get("details"),
        }
    except requests.exceptions.RequestException as e:
        return {"source": "EmailRep", "error": f"Request error: {str(e)}"}