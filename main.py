from dotenv import load_dotenv
load_dotenv()

from handlers.hash_handler import verify_hash
from handlers.domain_handler import verify_domain
from handlers.ip_handler import verify_ip
from handlers.url_handler import verify_url
from handlers.email_handler import verify_email
from utils.validators import is_valid_hash, is_valid_domain, is_valid_ip, is_valid_url, is_valid_email

def menu():
    while True:
        print("\n==== IOC Checker Menu ====")
        print("1. Check a hash")
        print("2. Check a domain")
        print("3. Check an IP address")
        print("4. Check a URL")
        print("5. Check an email")
        print("0. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            ioc = input("Enter hash: ").strip()
            if not is_valid_hash(ioc):
                print("[!] Invalid hash format. Please enter a valid MD5, SHA-1, or SHA-256 hash.")
                continue
            results = verify_hash(ioc)
            display_results(results)
        elif choice == "2":
            ioc = input("Enter domain: ").strip()
            if not is_valid_domain(ioc):
                print("[!] Invalid domain format. Please try again.")
                continue
            results = verify_domain(ioc)
            display_results(results)
        elif choice == "3":
            ioc = input("Enter IP: ").strip()
            if not is_valid_ip(ioc):
                print("[!] Invalid IP address format. Please try again.")
                continue
            results = verify_ip(ioc)
            display_results(results)
        elif choice == "4":
            ioc = input("Enter URL: ").strip()
            if not is_valid_url(ioc):
                print("[!] Invalid URL format. Please ensure it starts with http:// or https://.")
                continue
            results = verify_url(ioc)
            display_results(results)
        elif choice == "5":
            ioc = input("Enter email: ").strip()
            if not is_valid_email(ioc):
                print("[!] Invalid email format. Please try again.")
                continue
            results = verify_email(ioc)
            display_results(results)
        elif choice == "0":
            print("Exiting the program.")
            break
        else:
            print("[!] Invalid option. Please try again.")

def display_results(results):
    print("\n--- Results ---")
    for r in results:
        print(f"Source: {r.get('source')}")
        if r.get("error"):
            print(f"  Error: {r['error']}")
        else:
            for k,v in r.items():
                if k != "source":
                    print(f"  {k}: {v}")
        print("")

if __name__ == "__main__":
    menu()