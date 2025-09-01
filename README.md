# IOC-Checker

Small tool to check Indicators of Compromise (hashes, domains, IPs, URLs, emails) against local lists and several threat-intelligence APIs.

## Features
- Validate and check IOCs: MD5/SHA1/SHA256, domains, IPs, URLs, emails.
- Local IOC lists in the `data/` folder.
- Integrations with VirusTotal, AlienVault (OTX), AbuseIPDB, URLhaus, PhishTank, MalwareBazaar and EmailRep.
- Simple, interactive CLI.

## Quickstart
1. Install dependencies:
```powershell
pip install -r requirements.txt
```
2. Create a `.env` file in the project root with your API keys (see Environment variables).
3. Run the CLI:
```powershell
python main.py
```

## Environment variables
Add these to `.env`:
- VT_API_KEY
- ABUSEIPDB_API_KEY
- PHISHTANK_API_KEY
- MALWAREBAZAAR_API_KEY
- URLHAUS_API_KEY

## Project layout
- main.py — CLI entrypoint
- utils/validators.py — input validation helpers
- data/ — local IOC lists (domain_iocs.py, hash_iocs.py, ip_iocs.py, url_iocs.py)
- handlers/ — orchestration per IOC type
- api/ — API client modules for external services
- requirements.txt — Python dependencies

## Notes
- The CLI validates input before querying APIs.
- Check API rate limits and usage policies for each service.