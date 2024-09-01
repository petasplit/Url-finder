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
common_paths = [
    'admin', 'login', 'dashboard', 'hidden', '.git', '.env', 'api', 
    'config', 'uploads', 'backup', 'backups', 'database', 'db', 
    'js', 'css', 'assets', 'private', 'secret', 'tmp', 'temp', 
    'old', 'test', 'staging', 'logs', 'robots.txt', 'sitemap.xml',
    'cgi-bin', 'index.php', 'index.html', 'index.asp', 'wp-admin', 
    'wp-login.php', 'user', 'signup', 'register', 'auth', 'signin', 
    'checkout', 'cart', 'store', 'catalog', 'product', 'category', 
    'image', 'images', 'img', 'scripts', 'media', 'admin.php',
    'forgot-password', 'reset-password', 'account', 'settings', 
    'profile', 'debug', 'v1', 'v2', 'v3', 'v4', 'beta', 'alpha', 
    'version', 'api/v1', 'api/v2', 'api/v3', 'old', 'new', 'secure',
    'private', 'adminarea', 'editor', 'panel', 'control', 'manager',
    'manage', 'bin', 'core', 'public', 'restricted', 'api/hidden',
    'uploads/hidden', 'downloads', 'docs', 'documentation', 
    'includes', 'inc', 'src', 'source', 'code', 'shell', 'dev',
    'development', 'lib', 'library', 'vendor', 'plugins', 'modules',
    'cgi', 'phpmyadmin', 'mysql', 'adminpanel', 'testadmin', 
    'controlpanel', 'securepanel', 'services', 'connect', 'contact'
]

common_query_params = [
    'id', 'page', 'search', 'query', 'lang', 'view', 'category', 
    'product', 'type', 'filter', 'item', 'sort', 'order', 'key', 
    'token', 'session', 'user', 'password', 'login', 'redirect', 
    'next', 'source', 'ref', 'referrer', 'email', 'file', 'action',
    'do', 'cmd', 'exec', 'process', 'state', 'status', 'dir', 
    'directory', 'module', 'plugin', 'extension', 'theme', 
    'template', 'admin', 'config', 'debug', 'debugger', 'log',
    'file', 'report', 'trace', 'download', 'fetch', 'save', 'restore',
    'get', 'put', 'post', 'update', 'delete', 'remove', 'create',
    'insert', 'update', 'delete', 'backup', 'restore', 'install', 
    'uninstall', 'setup', 'init', 'initialize', 'migration', 
    'import', 'export', 'load', 'save', 'upload', 'download',
    'change', 'modify', 'rename', 'copy', 'move', 'print', 'printable'
]

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
async def periodic_save(filename, interval=10):
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
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' in content_type:
                        return await response.json()
                    else:
                        return await response.text()
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
        if isinstance(wayback_response, str):
            wayback_urls = wayback_response.splitlines()
            urls.update(wayback_urls)
            logger.info(f"Discovered {len(wayback_urls)} URLs from Wayback Machine")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from Wayback Machine: {e}")
    
    # crt.sh (Certificate Transparency Logs)
    crtsh_url = f"https://crt.sh/?q={domain}&output=json"
    try:
        crtsh_data = await fetch_external_data(crtsh_url)
        if isinstance(crtsh_data, list):
            crtsh_urls = [entry['common_name'] for entry in crtsh_data if domain in entry['common_name']]
            urls.update(crtsh_urls)
            logger.info(f"Discovered {len(crtsh_urls)} URLs from crt.sh")
        else:
            logger.error(f"Failed to fetch URLs from crt.sh: Expected a list, got {type(crtsh_data).__name__}")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from crt.sh: {e}")
    
    # Common Crawl URLs
    common_crawl_url = f"https://index.commoncrawl.org/CC-MAIN-2023-18-index?url={domain}&output=json"
    try:
        cc_data = await fetch_external_data(common_crawl_url)
        if isinstance(cc_data, list):
            cc_urls = [entry['url'] for entry in cc_data]
            urls.update(cc_urls)
            logger.info(f"Discovered {len(cc_urls)} URLs from Common Crawl")
        else:
            logger.error(f"Failed to fetch URLs from Common Crawl: Expected a list, got {type(cc_data).__name__}")
    except aiohttp.ClientResponseError as e:
        if e.status == 404:
            logger.warning("Common Crawl data not found.")
        else:
            logger.error(f"Failed to fetch URLs from Common Crawl: {e}")
    
    # AlienVault OTX URLs
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    try:
        otx_data = await fetch_external_data(otx_url)
        if isinstance(otx_data, dict):
            otx_urls = [entry['url'] for entry in otx_data.get('url_list', [])]
            urls.update(otx_urls)
            logger.info(f"Discovered {len(otx_urls)} URLs from AlienVault OTX")
        else:
            logger.error(f"Failed to fetch URLs from AlienVault OTX: Expected a dict, got {type(otx_data).__name__}")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from AlienVault OTX: {e}")
    
    # Additional Services
    services = [
        {"name": "Shodan", "url": f"https://api.shodan.io/shodan/host/search?query=hostname:{domain}&key=YOUR_API_KEY"},
        {"name": "SecurityTrails", "url": f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", "headers": {"APIKEY": "YOUR_API_KEY"}},
        {"name": "Hunter.io", "url": f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key=YOUR_API_KEY"},
        {"name": "Censys", "url": f"https://search.censys.io/api/v1/search/hosts?query={domain}", "headers": {"Authorization": "Basic YOUR_API_KEY"}},
        {"name": "GreyNoise", "url": f"https://api.greynoise.io/v3/search/actor?query=domain:{domain}", "headers": {"Authorization": "Bearer YOUR_API_KEY"}},
        {"name": "Spyse", "url": f"https://api.spyse.com/v4/data/domain/subdomains?domain={domain}&token=YOUR_API_KEY"},
        {"name": "Have I Been Pwned", "url": f"https://haveibeenpwned.com/api/v3/breachedaccount/{domain}", "headers": {"User-Agent": "YourAppName"}},
        {"name": "Snyk", "url": f"https://snyk.io/api/v1/organizations/{domain}/projects", "headers": {"Authorization": "token YOUR_API_KEY"}},
        {"name": "HackerTarget", "url": f"https://api.hackertarget.com/hostsearch/?q={domain}"},
        {"name": "URLScan.io", "url": f"https://urlscan.io/api/v1/search/?q={domain}"}
    ]
    
    for service in services:
        try:
            response_data = await fetch_external_data(service["url"], headers=service.get("headers"))
            if isinstance(response_data, dict):
                urls.update(response_data.get("urls", []))
                logger.info(f"Discovered URLs from {service['name']}")
            elif isinstance(response_data, list):
                urls.update([entry.get('url') for entry in response_data])
                logger.info(f"Discovered URLs from {service['name']}")
            else:
                logger.error(f"Failed to fetch URLs from {service['name']}: Unexpected response format")
        except Exception as e:
            logger.error(f"Failed to fetch URLs from {service['name']}: {e}")

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
