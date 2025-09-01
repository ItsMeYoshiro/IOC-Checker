from data.hash_iocs import load_hash_iocs
from api.api_virustotal import virustotal_report
from api.api_malwarebazaar import malwarebazaar_report
from api.api_alienvault import alienvault_report

def verify_hash(ioc):
    results = []

    if ioc in load_hash_iocs():
        results.append({"source": "Local List", "found": True})

    vt_result = virustotal_report(ioc, "hash")
    if vt_result:
        results.append(vt_result)

    mb_result = malwarebazaar_report(ioc)
    if mb_result:
        results.append(mb_result)

    av_result = alienvault_report("file", ioc)
    if av_result:
        results.append(av_result)

    return results
