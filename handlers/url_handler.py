from data.url_iocs import load_url_iocs
from api.api_virustotal import virustotal_report
from api.api_urlhaus import urlhaus_report
from api.api_phishtank import phishtank_report
from api.api_alienvault import alienvault_report

def verify_url(ioc):
    results = []

    if ioc in load_url_iocs():
        results.append({"source": "Local List", "found": True})

    vt_result = virustotal_report(ioc, "url")
    if vt_result:
        results.append(vt_result)

    uh_result = urlhaus_report(ioc)
    if uh_result:
        results.append(uh_result)

    pt_result = phishtank_report(ioc)
    if pt_result:
        results.append(pt_result)

    av_result = alienvault_report("url", ioc)
    if av_result:
        results.append(av_result)

    return results
