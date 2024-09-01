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
    
    # Extract all links from the page
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        full_url = urljoin(url, href)
        if domain in urlparse(full_url).netloc:
            discovered_urls.add(full_url)
    
    # Extract JavaScript URLs
    for script in soup.find_all('script', src=True):
        src = script.get('src')
        full_url = urljoin(url, src)
        if domain in urlparse(full_url).netloc:
            discovered_urls.add(full_url)
    
    # Extract form actions
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
    # Prompt the user for a starting URL
    start_url = input("Enter the starting URL: ").strip()
    max_depth = int(input("Enter the maximum depth to scrape (e.g., 5): ").strip())
    max_tasks = int(input("Enter the maximum number of concurrent tasks (e.g., 20): ").strip())

    domain = urlparse(start_url).netloc
    output_filename = f'discovered_urls_{int(time.time())}.txt'
    
    # Fetch URLs from external sources
    external_urls = await fetch_external_urls(domain)
    discovered_urls.update(external_urls)

    async with ClientSession() as session:
        # Start periodic save task
        save_task = asyncio.create_task(periodic_save(output_filename))

        # Scrape the starting URL and other discovered URLs
        all_urls = await recursive_scrape(start_url, session, max_depth=max_depth, current_depth=0, visited=set(), max_tasks=max_tasks)
        all_urls.update(discovered_urls)
        
        # Save the results to a file with only discovered URLs
        discovered_urls.update(all_urls)
        save_urls(output_filename)
        
        # Wait for the termination signal
        while not terminate_script:
            await asyncio.sleep(1)
        
        # Cancel the periodic save task
        save_task.cancel()
        try:
            await save_task
        except asyncio.CancelledError:
            pass

if __name__ == "__main__":
    asyncio.run(main())
