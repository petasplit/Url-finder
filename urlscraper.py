import asyncio
import aiohttp
import re
import logging
import time
import os
import signal
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import subprocess
import shlex

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variable to store discovered URLs
discovered_urls = set()

# Comprehensive list of common hidden directories, files, and query parameters
common_paths = [ ... ]  # as before
common_query_params = [ ... ]  # as before

# Global variable to control script termination
terminate_script = False

def signal_handler(sig, frame):
    global terminate_script
    logger.info("Termination signal received, finishing up...")
    terminate_script = True

# Attach signal handler
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Function to save discovered URLs periodically
async def periodic_save(filename, interval=60):
    while not terminate_script:
        await asyncio.sleep(interval)
        logger.info(f"Periodic save: saving discovered URLs to {filename}")
        save_urls(filename)

def save_urls(filename):
    with open(filename, 'w') as f:
        for url in discovered_urls:
            f.write(url + "\n")
    logger.info(f"URLs saved to {filename}")

# Function to fetch and parse a URL
async def fetch_and_parse(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                html = await response.text()
                return BeautifulSoup(html, 'html.parser')
            else:
                logger.warning(f"Failed to fetch {url}: Status {response.status}")
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
    return None

# Function to discover URLs from the starting page
async def discover_urls(session, url, domain):
    soup = await fetch_and_parse(session, url)
    if not soup:
        return set()
    
    discovered_urls = set()
    
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        full_url = urljoin(url, href)
        if domain in urlparse(full_url).netloc:
            discovered_urls.add(full_url)
    
    for script in soup.find_all('script', src=True):
        src = script.get('src')
        full_url = urljoin(url, src)
        if domain in urlparse(full_url).netloc:
            discovered_urls.add(full_url)
    
    for form in soup.find_all('form', action=True):
        action = form.get('action')
        full_url = urljoin(url, action)
        if domain in urlparse(full_url).netloc:
            discovered_urls.add(full_url)
    
    return discovered_urls

# Function to discover hidden endpoints using common paths and query parameters
async def discover_hidden_urls(url):
    discovered_urls = set()
    base_url = url.rstrip('/')

    for path in common_paths:
        full_url = f"{base_url}/{path}"
        discovered_urls.add(full_url)

    for param in common_query_params:
        full_url = f"{base_url}?{param}=test"
        discovered_urls.add(full_url)

    return discovered_urls

# Function to fetch external data
async def fetch_external_data(url, headers=None):
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as response:
            if response.status == 200:
                try:
                    return await response.json()
                except aiohttp.ContentTypeError:
                    logger.warning(f"Unexpected MIME type for URL {url}")
                    return await response.text()
            else:
                response.raise_for_status()

# Function to fetch URLs from external sources
async def fetch_external_urls(domain):
    urls = set()
    
    # Wayback Machine URLs
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&fl=original&collapse=urlkey"
    try:
        wayback_response = await fetch_external_data(wayback_url)
        wayback_urls = wayback_response.splitlines()
        urls.update(wayback_urls)
        logger.info(f"Discovered {len(wayback_urls)} URLs from Wayback Machine")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from Wayback Machine: {e}")
    
    # VirusTotal URLs
    vt_url = f"https://www.virustotal.com/ui/domains/{domain}/urls?limit=40"
    try:
        vt_data = await fetch_external_data(vt_url)
        vt_urls = [item['attributes']['url'] for item in vt_data['data']]
        urls.update(vt_urls)
        logger.info(f"Discovered {len(vt_urls)} URLs from VirusTotal")
    except aiohttp.ClientResponseError as e:
        if e.status == 429:
            logger.warning("Rate limit exceeded for VirusTotal. Implementing retry strategy is advised.")
        else:
            logger.error(f"Failed to fetch URLs from VirusTotal: {e}")
    
    # crt.sh (Certificate Transparency Logs)
    crtsh_url = f"https://crt.sh/?q={domain}&output=json"
    try:
        crtsh_data = await fetch_external_data(crtsh_url)
        crtsh_urls = re.findall(rf'"common_name":"(.*?{domain})"', crtsh_data)
        urls.update(crtsh_urls)
        logger.info(f"Discovered {len(crtsh_urls)} URLs from crt.sh")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from crt.sh: {e}")
    
    # Common Crawl URLs
    common_crawl_url = f"https://index.commoncrawl.org/CC-MAIN-2023-18-index?url={domain}&output=json"
    try:
        cc_data = await fetch_external_data(common_crawl_url)
        cc_urls = [entry['url'] for entry in cc_data]
        urls.update(cc_urls)
        logger.info(f"Discovered {len(cc_urls)} URLs from Common Crawl")
    except aiohttp.ClientResponseError as e:
        if e.status == 404:
            logger.warning("Common Crawl data not found.")
        else:
            logger.error(f"Failed to fetch URLs from Common Crawl: {e}")
    
    # AlienVault OTX URLs
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    try:
        otx_data = await fetch_external_data(otx_url)
        otx_urls = [entry['url'] for entry in otx_data['url_list']]
        urls.update(otx_urls)
        logger.info(f"Discovered {len(otx_urls)} URLs from AlienVault OTX")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from AlienVault OTX: {e}")
    
    # PublicWWW URLs
    public_www_url = f"https://publicwww.com/websites/{domain}/"
    try:
        public_www_response = subprocess.check_output(shlex.split(f"curl -s '{public_www_url}'"))
        public_www_data = public_www_response.decode()
        public_www_urls = re.findall(r'href="([^"]*?{domain}[^"]*?)"', public_www_data)
        urls.update(public_www_urls)
        logger.info(f"Discovered {len(public_www_urls)} URLs from PublicWWW")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from PublicWWW: {e}")
    
    # URLScan.io URLs
    urlscan_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
    try:
        urlscan_data = await fetch_external_data(urlscan_url)
        urlscan_urls = [result['task']['url'] for result in urlscan_data['results']]
        urls.update(urlscan_urls)
        logger.info(f"Discovered {len(urlscan_urls)} URLs from URLScan.io")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from URLScan.io: {e}")
    
    # SecurityTrails URLs
    securitytrails_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        headers = {'APIKEY': 'YOUR_API_KEY_HERE'}
        securitytrails_data = await fetch_external_data(securitytrails_url, headers=headers)
        securitytrails_urls = [f"http://{subdomain}.{domain}" for subdomain in securitytrails_data['subdomains']]
        urls.update(securitytrails_urls)
        logger.info(f"Discovered {len(securitytrails_urls)} URLs from SecurityTrails")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from SecurityTrails: {e}")

    return urls

# Recursive function to scrape URLs
async def recursive_scrape(url, session, max_depth, current_depth, visited, max_tasks):
    if current_depth > max_depth or terminate_script:
        return visited

    logger.info(f"Scraping URL: {url} at depth {current_depth}")
    urls_to_visit = await discover_urls(session, url, urlparse(url).netloc)
    urls_to_visit.update(await discover_hidden_urls(url))

    semaphore = asyncio.Semaphore(max_tasks)

    async def visit_url(url):
        async with semaphore:
            if url not in visited and urlparse(url).netloc == urlparse(url).netloc:
                visited.add(url)
                logger.info(f"Found URL: {url}")
                await recursive_scrape(url, session, max_depth, current_depth + 1, visited, max_tasks)

    tasks = [visit_url(url) for url in urls_to_visit if url not in visited]
    await asyncio.gather(*tasks)

    return visited

# Main function
async def main():
    global discovered_urls
    
    # Prompt the user for a starting URL
    start_url = input("Enter the starting URL: ").strip()
    max_depth = int(input("Enter the maximum depth to scrape (e.g., 5): ").strip())
    max_tasks = int(input("Enter the maximum number of concurrent tasks (e.g., 20): ").strip())

    domain = urlparse(start_url).netloc

    # Prepare filename for periodic saving
    timestamp = int(time.time())
    save_filename = f'discovered_urls_{timestamp}.txt'

    # Start periodic saving task
    periodic_save_task = asyncio.create_task(periodic_save(save_filename))

    # Fetch URLs from external sources
    external_urls = await fetch_external_urls(domain)

    async with ClientSession() as session:
        # Scrape the starting URL and other discovered URLs
        all_urls = await recursive_scrape(start_url, session, max_depth=max_depth, current_depth=0, visited=set(), max_tasks=max_tasks)
        all_urls.update(external_urls)
        
        # Save the results to a file with only discovered URLs
        discovered_urls.update(all_urls)
        save_urls(save_filename)
        
        logger.info(f"Total URLs found: {len(discovered_urls)}")
        logger.info(f"Results saved to {save_filename}")

    # Cancel periodic save task
    periodic_save_task.cancel()
    try:
        await periodic_save_task
    except asyncio.CancelledError:
        pass

# Run the script
if __name__ == "__main__":
    asyncio.run(main())
