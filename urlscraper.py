import asyncio
import aiohttp
from aiohttp import ClientSession
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse, urlunparse
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define commonly used hidden directories, files, subdomains, and query parameters
common_paths = [
    'admin', 'login', 'dashboard', 'hidden', '.git', '.env', 'api', 
    'config', 'uploads', 'backup', 'backups', 'database', 'db', 
    'js', 'css', 'assets', 'private', 'secret', 'tmp', 'temp', 
    'old', 'test', 'staging', 'logs', 'robots.txt', 'sitemap.xml'
]

common_subdomains = [
    'www', 'admin', 'mail', 'blog', 'dev', 'test', 'api', 'staging', 
    'shop', 'support', 'help', 'portal'
]

common_query_params = [
    'id', 'page', 'search', 'query', 'lang', 'view', 'category', 
    'product', 'type', 'filter'
]

# Function to scrape URLs from a given URL
async def scrape_urls(session, start_url, max_retries=3):
    urls = set()
    retries = 0
    success = False

    while retries < max_retries and not success:
        try:
            async with session.get(start_url) as response:
                if response.status != 200:
                    logger.warning(f"Error accessing {start_url}: Status {response.status}")
                    return urls

                content_type = response.headers.get('Content-Type', '').lower()
                text = await response.text()

                if 'text/html' in content_type:
                    # Scrape URLs from HTML
                    soup = BeautifulSoup(text, 'html.parser')
                    for tag in soup.find_all(['a', 'link', 'script', 'iframe', 'img']):
                        href = tag.get('href')
                        src = tag.get('src')
                        if href:
                            urls.add(urljoin(start_url, href))
                        if src:
                            urls.add(urljoin(start_url, src))

                    # Scrape URLs from JavaScript
                    js_urls = re.findall(r'''(?:"|')(https?://.*?)(?:"|')''', text)
                    for js_url in js_urls:
                        urls.add(js_url)

                    # Add hidden and common paths
                    for path in common_paths:
                        full_url = urljoin(start_url, path)
                        urls.add(full_url)

                    success = True

                # Fetch robots.txt if available
                if 'robots.txt' not in start_url:
                    robots_url = urljoin(start_url, 'robots.txt')
                    try:
                        async with session.get(robots_url) as robots_response:
                            if robots_response.status == 200:
                                for line in (await robots_response.text()).splitlines():
                                    if line.lower().startswith('disallow:'):
                                        path = line.split(':', 1)[1].strip()
                                        if path:
                                            disallowed_url = urljoin(start_url, path)
                                            urls.add(disallowed_url)
                    except aiohttp.ClientError:
                        pass

        except aiohttp.ClientError as e:
            logger.error(f"Request failed for {start_url}: {e}")
            retries += 1
            await asyncio.sleep(2 ** retries)

    return urls

# Function to discover subdomains
async def discover_subdomains(session, base_url):
    urls = set()
    parsed_url = urlparse(base_url)
    base_domain = parsed_url.netloc

    for subdomain in common_subdomains:
        subdomain_url = f"http://{subdomain}.{base_domain}"
        try:
            async with session.get(subdomain_url) as response:
                if response.status == 200:
                    logger.info(f"Discovered subdomain: {subdomain_url}")
                    urls.add(subdomain_url)
        except aiohttp.ClientError:
            pass

    return urls

# Function to discover URLs by appending common query parameters
async def discover_query_urls(session, base_url):
    urls = set()

    for param in common_query_params:
        query_url = f"{base_url}?{param}=1"
        try:
            async with session.get(query_url) as response:
                if response.status == 200:
                    logger.info(f"Discovered query URL: {query_url}")
                    urls.add(query_url)
        except aiohttp.ClientError:
            pass

    return urls

# Function to recursively scrape URLs up to a certain depth with concurrency
async def recursive_scrape(start_url, session, max_depth=2, current_depth=0, visited=None, max_tasks=10):
    if visited is None:
        visited = set()

    if current_depth > max_depth:
        return visited

    urls_to_visit = await scrape_urls(session, start_url)
    urls_to_visit.update(await discover_subdomains(session, start_url))
    urls_to_visit.update(await discover_query_urls(session, start_url))

    tasks = []
    semaphore = asyncio.Semaphore(max_tasks)

    async def visit_url(url):
        async with semaphore:
            if url not in visited:
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
    max_depth = int(input("Enter the maximum depth to scrape (e.g., 3): ").strip())
    max_tasks = int(input("Enter the maximum number of concurrent tasks (e.g., 10): ").strip())

    async with ClientSession() as session:
        all_urls = await recursive_scrape(start_url, session, max_depth=max_depth, max_tasks=max_tasks)
        
        # Save the results to a file
        timestamp = int(time.time())
        output_file = f'scraped_urls_{timestamp}.txt'
        with open(output_file, 'w') as f:
            for url in all_urls:
                f.write(url + "\n")
        
        logger.info(f"Total URLs found: {len(all_urls)}")
        logger.info(f"Results saved to {output_file}")

# Run the script
if __name__ == "__main__":
    asyncio.run(main())
