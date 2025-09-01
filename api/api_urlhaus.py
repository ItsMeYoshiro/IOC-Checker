import os
import requests
import json

# Endpoint da API v1 para consultar uma URL
API_URL = "https://urlhaus-api.abuse.ch/v1/url/" 
# Carrega a chave de API do ambiente
API_KEY = os.getenv("URLHAUS_API_KEY")

def urlhaus_report(url):
    # O script usa 'Auth-Key', então vamos usar esse cabeçalho
    headers = {}
    if API_KEY:
        headers['Auth-Key'] = API_KEY
    else:
        # Se não houver chave, a API pode não funcionar, mas informamos o usuário
        return {"source": "URLhaus", "error": "URLhaus API Key not found in .env file."}

    try:
        payload = {'url': url}
        response = requests.post(API_URL, headers=headers, data=payload)

        # Verificação de erros de conexão/HTTP
        if response.status_code != 200:
            return {"source": "URLhaus", "error": f"HTTP Status {response.status_code}", "details": response.text[:200]}

        # Verificação de erro de decodificação de JSON
        data = response.json()

        # Lógica de interpretação da resposta, agora retornando um dicionário
        if data.get("query_status") == "ok":
            return {
                "source": "URLhaus",
                "threat": data.get("threat"),
                "host": data.get("host"),
                "url_status": data.get("url_status"),
                "tags": data.get("tags"),
            }
        elif data.get("query_status") == "no_results":
             return {"source": "URLhaus", "info": "URL not found in database."}
        else:
            return {"source": "URLhaus", "info": data.get("query_status")}
            
    except json.JSONDecodeError:
        return {"source": "URLhaus", "error": "Failed to decode JSON response.", "details": response.text[:200]}
    except requests.exceptions.RequestException as e:
        return {"source": "URLhaus", "error": str(e)}