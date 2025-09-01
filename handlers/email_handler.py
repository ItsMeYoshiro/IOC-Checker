from api.api_emailrep import emailrep_report
from api.api_virustotal import virustotal_email_report

def verify_email(email):
    results = []
    results.append(emailrep_report(email))
    results.append(virustotal_email_report(email))
    return results