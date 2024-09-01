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
import signal
import os

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
        headers = {
            "APIKEY": "YOUR_SECURITY_TRAILS_API_KEY"
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(securitytrails_url, headers=headers) as response:
                if response.status == 200:
                    securitytrails_data = await response.json()
                    st_urls = [f"http://{subdomain}.{domain}" for subdomain in securitytrails_data['subdomains']]
                    urls.update(st_urls)
                    logger.info(f"Discovered {len(st_urls)} URLs from SecurityTrails")
                else:
                    logger.warning(f"Failed to fetch URLs from SecurityTrails: Status {response.status}")
    except Exception as e:
        logger.error(f"Failed to fetch URLs from SecurityTrails: {e}")

    return urls

# URL discovery function using BeautifulSoup
async def discover_urls(session, url, domain):
    try:
        async with session.get(url) as response:
            if response.status == 200:
                soup = BeautifulSoup(await response.text(), 'html.parser')

                # Extract links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('/'):
                        full_url = urljoin(url, href)
                    elif href.startswith('http'):
                        full_url = href
                    else:
                        full_url = None
                    
                    if full_url and domain in urlparse(full_url).netloc:
                        discovered_urls.add(full_url)
                        logger.info(f"Discovered URL: {full_url}")

                # Check for common hidden directories and files
                for path in common_paths:
                    test_url = urljoin(url, path)
                    discovered_urls.add(test_url)
                    logger.info(f"Generated URL: {test_url}")

                # Check for common query parameters
                for param in common_query_params:
                    for value in ['1', 'true', 'admin', 'test']:
                        test_url = f"{url}?{param}={value}"
                        discovered_urls.add(test_url)
                        logger.info(f"Generated URL with query parameter: {test_url}")
    except Exception as e:
        logger.error(f"Error discovering URLs at {url}: {e}")

# Function to start the web server for the discovered URLs
def start_web_server(port=8080):
    if os.path.exists('discovered_urls.txt'):
        command = f"python3 -m http.server {port}"
        process = subprocess.Popen(shlex.split(command))
        logger.info(f"Serving discovered URLs on http://localhost:{port}")
        return process
    else:
        logger.error("discovered_urls.txt not found. Cannot start web server.")
        return None

# Main function
async def main(domain, output_filename):
    # Initialize HTTP session
    async with aiohttp.ClientSession() as session:
        # Fetch external URLs
        external_urls = await fetch_external_urls(domain)
        discovered_urls.update(external_urls)

        # Start URL discovery
        logger.info("Starting URL discovery...")
        await discover_urls(session, f"http://{domain}", domain)
        
        # Start periodic save task
        save_task = asyncio.create_task(periodic_save(output_filename))
        
        # Wait for the termination signal
        while not terminate_script:
            await asyncio.sleep(1)
        
        # Save final discovered URLs
        save_urls(output_filename)
        
        # Cancel the periodic save task
        save_task.cancel()

if __name__ == '__main__':
    domain = 'example.com'  # Replace with the target domain
    output_filename = 'discovered_urls.txt'
    
    # Start the main process
    asyncio.run(main(domain, output_filename))
    
    # Start web server to serve the discovered URLs
    process = start_web_server(port=8080)

    # Wait for termination signal to stop the web server
    while not terminate_script:
        time.sleep(1)
    
    if process:
        process.terminate()
        logger.info("Web server stopped.")
