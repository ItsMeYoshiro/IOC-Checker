from data.ip_iocs import load_ip_iocs
from api.api_virustotal import virustotal_report
from api.api_abuseipdb import abuseipdb_report
from api.api_alienvault import alienvault_report

def verify_ip(ioc):
    results = []

    if ioc in load_ip_iocs():
        results.append({"source": "Local List", "found": True})

    vt_result = virustotal_report(ioc, "ip")
    if vt_result:
        results.append(vt_result)

    abuse_result = abuseipdb_report(ioc)
    if abuse_result:
        results.append(abuse_result)

    av_result = alienvault_report("IPv4", ioc)
    if av_result:
        results.append(av_result)

    return results
