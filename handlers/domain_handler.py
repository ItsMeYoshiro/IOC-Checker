from data.domain_iocs import load_domain_iocs
from api.api_virustotal import virustotal_report
from api.api_alienvault import alienvault_report

def verify_domain(ioc):
    results = []

    if ioc in load_domain_iocs():
        results.append({"source": "Local List", "found": True})

    vt_result = virustotal_report(ioc, "domain")
    if vt_result:
        results.append(vt_result)

    av_result = alienvault_report("domain", ioc)
    if av_result:
        results.append(av_result)

    return results
