import nmap
import nmap3
import json
import requests
from bs4 import BeautifulSoup
import asyncio
import aiohttp

domain = "tjara.com"
url="https://"+domain



# ----------------------------------------------------------------------------------------------


# nmap

def nmap_scan(domain):
        
    nmap = nmap3.Nmap()
    result = nmap.nmap_version_detection(domain)
    return result
    print("done 1")




#     # Create a new PortScanner instance
#     scanner = nmap.PortScanner()

#     # Set the desired options including "-T4"
#     scanner.arguments = "-T4 -p 80,443,8080"

#     # Scan a target
#     result = scanner.scan("127.0.0.1")

#     # Print scan results
#     return result


nmapp=nmap_scan(domain)


# ----------------------------------------------------------------------------------------------


# subdomain 

async def check_subdomain(subdomain, domain, session):
    url = f"http://{subdomain}.{domain}"
    try:
        async with session.get(url) as response:
            if response.status == 200:
                return url
    except:
        pass

async def subdomain_scan(domain):
    discovered_subdomains = []
    async with aiohttp.ClientSession() as session:
        with open("subdomains.txt") as file:
            subdomains = file.read().splitlines()
        tasks = []
        for subdomain in subdomains:
            task = asyncio.ensure_future(check_subdomain(subdomain, domain, session))
            tasks.append(task)
        results = await asyncio.gather(*tasks)
        discovered_subdomains = [url for url in results if url is not None]
    print(discovered_subdomains)
    
    return discovered_subdomains

subdomains = asyncio.run(subdomain_scan(domain))



# ----------------------------------------------------------------------------------------------


# get links

def get_links(url):
    
    # response = requests.get(url)
    response = requests.get('https://tjara.com', verify=False)
    soup = BeautifulSoup(response.content, "html.parser")

    links = []
    for link in soup.find_all("a"):
        href = link.get("href")
        if href is not None:
            links.append(href)
    print("done 3")
    return links

links=get_links(url)


# ----------------------------------------------------------------------------------------------


# hunter
def get_emails(domain):
    url = 'https://api.hunter.io/v2/domain-search'
    params = {'domain': domain, 'api_key': 'c180ff5229f243e6be0a76ab900cefe1ba36113f'}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        print(data)
    else:
        print('Error:', response.status_code)

# hunter=get_emails(domain)

# ----------------------------------------------------------------------------------------------


# shodan and cve

def shodan(domain):
    import requests

    def search_host(hostname, api_key):
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{hostname}"
        
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            print(f"Error: {response.status_code}")
            return None

    def search_cves(ip_address, api_key):
        url = f"https://exploits.shodan.io/api/search?query={ip_address}&key={api_key}"
        
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return data
        else:
            print(f"Error: {response.status_code}")
            return None

    # Shodan API key
    api_key = "uVv1yDI0pXms2coWyGtsX3cInBkCJtkS"

    # hostname you want to search for
    hostname = domain

    # Search for the host using the hostname
    host_data = search_host(hostname, api_key)

    if host_data:
        if host_data['total'] > 0:
            ip_address = host_data['matches'][0]['ip_str']
            print(f"IP Address: {ip_address}")

            # Search for CVEs associated with the IP address
            cve_data = search_cves(ip_address, api_key)
            
            if cve_data:
                print(cve_data)
        else:
            print("No results found for the given hostname.")

# shodan1=shodan(domain)

# ----------------------------------------------------------------------------------------------


# writing in json file

report={
    "nmap":nmapp,
    "subdomains":subdomains, 
    "links":links,
    # "hunter":hunter,
    # "shidan":shodan1
}


with open('proj.json', 'w') as outfile:
    json.dump(report, outfile, indent=4)








