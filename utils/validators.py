import re

def is_valid_hash(hash_input: str) -> bool:
    pattern = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
    return pattern.match(hash_input) is not None

def is_valid_domain(domain: str) -> bool:
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9]"  # Começa com alfanumérico
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"  # Subdomínio opcional
        r"+[a-zA-Z]{2,6}$"  # TLD (Top-Level Domain)
    )
    return pattern.match(domain) is not None

def is_valid_ip(ip: str) -> bool:
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip) is not None

def is_valid_url(url: str) -> bool:
    pattern = re.compile(r"^https?://[^\s/$.?#].[^\s]*$")
    return pattern.match(url) is not None

def is_valid_email(email):
    # Regex simples para validação de e-mail
    return re.match(r"^[^@]+@[^@]+\.[^@]+$", email) is not None