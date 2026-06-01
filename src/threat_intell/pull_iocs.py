import requests
import json
import dotenv
import os

dotenv.load_dotenv()

def pull_iocs(api_url, api_key, days=1):
    headers = {
        "Auth-Key": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "query": "get_iocs",
        "days": days
    }
    response = requests.post(api_url, headers=headers, json=payload)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to pull IOCs: {response.status_code} - {response.text}")
    


if __name__ == "__main__":
    API_URL = "https://threatfox-api.abuse.ch/api/v1/"
    API_KEY = os.getenv("THREATFOX_API_KEY")
    iocs = pull_iocs(API_URL, API_KEY, days=7)
    if iocs:
        with open("iocs.json", "w") as f:
            json.dump(iocs, f, indent=4)