import asyncio
import aiohttp
from aiohttp import ClientSession
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import logging
import time
import subprocess
import shlex

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

# Additional external URL sources
async def fetch_external_urls(domain):
    urls = set()
    
    # Wayback Machine URLs
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&fl=original&collapse=urlkey"
    try:
        wayback_response = subprocess.check_output(shlex.split(f"curl -s '{wayback_url}'"))
        wayback_urls = wayback_response.decode().splitlines()
        urls.update(wayback_urls)
        logger.info(f"Discovered {len(wayback_urls)} URLs from Wayback Machine")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from Wayback Machine: {e}")
    
    # VirusTotal URLs
    vt_url = f"https://www.virustotal.com/ui/domains/{domain}/urls?limit=40"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(vt_url) as response:
                if response.status == 200:
                    data = await response.json()
                    vt_urls = [item['attributes']['url'] for item in data['data']]
                    urls.update(vt_urls)
                    logger.info(f"Discovered {len(vt_urls)} URLs from VirusTotal")
                else:
                    logger.warning(f"Failed to fetch URLs from VirusTotal: Status {response.status}")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from VirusTotal: {e}")
    
    # crt.sh (Certificate Transparency Logs)
    crtsh_url = f"https://crt.sh/?q={domain}&output=json"
    try:
        crtsh_response = subprocess.check_output(shlex.split(f"curl -s '{crtsh_url}'"))
        crtsh_data = crtsh_response.decode()
        crtsh_urls = re.findall(rf'"common_name":"(.*?{domain})"', crtsh_data)
        urls.update(crtsh_urls)
        logger.info(f"Discovered {len(crtsh_urls)} URLs from crt.sh")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from crt.sh: {e}")
    
    # Common Crawl URLs
    common_crawl_url = f"https://index.commoncrawl.org/CC-MAIN-2023-18-index?url={domain}&output=json"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(common_crawl_url) as response:
                if response.status == 200:
                    common_crawl_data = await response.json()
                    cc_urls = [entry['url'] for entry in common_crawl_data]
                    urls.update(cc_urls)
                    logger.info(f"Discovered {len(cc_urls)} URLs from Common Crawl")
                else:
                    logger.warning(f"Failed to fetch URLs from Common Crawl: Status {response.status}")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from Common Crawl: {e}")
    
    # AlienVault OTX URLs
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(otx_url) as response:
                if response.status == 200:
                    otx_data = await response.json()
                    otx_urls = [entry['url'] for entry in otx_data['url_list']]
                    urls.update(otx_urls)
                    logger.info(f"Discovered {len(otx_urls)} URLs from AlienVault OTX")
                else:
                    logger.warning(f"Failed to fetch URLs from AlienVault OTX: Status {response.status}")
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
        async with aiohttp.ClientSession() as session:
            async with session.get(urlscan_url) as response:
                if response.status == 200:
                    urlscan_data = await response.json()
                    urlscan_urls = [result['task']['url'] for result in urlscan_data['results']]
                    urls.update(urlscan_urls)
                    logger.info(f"Discovered {len(urlscan_urls)} URLs from URLScan.io")
                else:
                    logger.warning(f"Failed to fetch URLs from URLScan.io: Status {response.status}")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from URLScan.io: {e}")
    
    # SecurityTrails URLs
    securitytrails_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(securitytrails_url, headers={'APIKEY': 'YOUR_API_KEY_HERE'}) as response:
                if response.status == 200:
                    securitytrails_data = await response.json()
                    securitytrails_urls = [f"http://{subdomain}.{domain}" for subdomain in securitytrails_data['subdomains']]
                    urls.update(securitytrails_urls)
                    logger.info(f"Discovered {len(securitytrails_urls)} URLs from SecurityTrails")
                else:
                    logger.warning(f"Failed to fetch URLs from SecurityTrails: Status {response.status}")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from SecurityTrails: {e}")

    return urls

# Asynchronous function to fetch and parse a URL
async def fetch_and_parse(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                return soup
    except Exception as e:
        logger.error(f"Failed to fetch {url}: {e}")
    return None

# Function to discover URLs from the starting page
async def discover_urls(session, url):
    discovered_urls = set()
    soup = await fetch_and_parse(session, url)
    if soup:
        # Extract all links from the page
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            full_url = urljoin(url, href)
            discovered_urls.add(full_url)
        
        # Extract JavaScript URLs
        for script in soup.find_all('script', src=True):
            src = script.get('src')
            full_url = urljoin(url, src)
            discovered_urls.add(full_url)
        
        # Extract form actions
        for form in soup.find_all('form', action=True):
            action = form.get('action')
            full_url = urljoin(url, action)
            discovered_urls.add(full_url)

    return discovered_urls

# Function to discover hidden endpoints using common paths and query parameters
async def discover_hidden_urls(session, url):
    discovered_urls = set()
    base_url = url.rstrip('/')

    for path in common_paths:
        full_url = f"{base_url}/{path}"
        discovered_urls.add(full_url)

    for param in common_query_params:
        full_url = f"{base_url}?{param}=test"
        discovered_urls.add(full_url)

    return discovered_urls

# Recursive function to scrape URLs
async def recursive_scrape(url, session, max_depth, current_depth, visited, max_tasks):
    if current_depth > max_depth:
        return visited

    logger.info(f"Scraping URL: {url} at depth {current_depth}")
    urls_to_visit = await discover_urls(session, url)
    urls_to_visit.update(await discover_hidden_urls(session, url))

    tasks = []
    semaphore = asyncio.Semaphore(max_tasks)

    async def visit_url(url):
        async with semaphore:
            if url not in visited and urlparse(url).netloc == urlparse(url).netloc:
                visited.add(url)
                logger.info(f"Found URL: {url}")
                await recursive_scrape(url, session, max_depth, current_depth + 1, visited, max_tasks)

    for url in urls_to_visit:
        if url not in visited:
            tasks.append(visit_url(url))

    await asyncio.gather(*tasks)

    return visited

# Main function
async def main():
    # Prompt the user for a starting URL
    start_url = input("Enter the starting URL: ").strip()
    max_depth = int(input("Enter the maximum depth to scrape (e.g., 5): ").strip())
    max_tasks = int(input("Enter the maximum number of concurrent tasks (e.g., 20): ").strip())

    domain = urlparse(start_url).netloc

    # Fetch URLs from external sources
    external_urls = await fetch_external_urls(domain)

    async with ClientSession() as session:
        # Scrape the starting URL and other discovered URLs
        all_urls = await recursive_scrape(start_url, session, max_depth=max_depth, current_depth=0, visited=set(), max_tasks=max_tasks)
        all_urls.update(external_urls)
        
        # Save the results to a file with only discovered URLs
        discovered_urls = list(all_urls)
        timestamp = int(time.time())
        output_file = f'discovered_urls_{timestamp}.txt'
        with open(output_file, 'w') as f:
            for url in discovered_urls:
                f.write(url + "\n")
        
        logger.info(f"Total URLs found: {len(discovered_urls)}")
        logger.info(f"Results saved to {output_file}")

# Run the script
if __name__ == "__main__":
    asyncio.run(main())
