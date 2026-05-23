import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

def print_info(msg):
    print(Fore.CYAN + "[*] " + msg)

def print_success(msg):
    print(Fore.GREEN + "[+] " + msg)

def print_warning(msg):
    print(Fore.YELLOW + "[!] " + msg)

def print_error(msg):
    print(Fore.RED + "[-] " + msg)

def get_page(url, timeout=10):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (WebVulnScanner/1.0)"}
        response = requests.get(url, headers=headers, timeout=timeout)
        return response
    except requests.exceptions.ConnectionError:
        print_error(f"Could not connect to {url}")
        return None
    except requests.exceptions.Timeout:
        print_error(f"Connection timed out for {url}")
        return None
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        return None

def get_all_forms(url):
    response = get_page(url)
    if response is None:
        return []
    soup = BeautifulSoup(response.content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    target_url = url if form_details["action"] == "" else form_details["action"]
    if not target_url.startswith("http"):
        target_url = url + "/" + target_url
    data = {}
    for input in form_details["inputs"]:
        if input["type"] in ("text", "search") or input["type"] == "password":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value", "")
        if input_name:
            data[input_name] = input_value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)