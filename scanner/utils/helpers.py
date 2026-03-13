from urllib.parse import urlparse, urljoin

def normalize_url(base_url, relative_url):
    """Normalizes a relative URL to an absolute URL based on the domain."""
    return urljoin(base_url, relative_url)

def is_same_domain(url1, url2):
    """Checks if two URLs share the same network location."""
    return urlparse(url1).netloc == urlparse(url2).netloc

def get_base_url(url):
    """Returns the base schema and domain from a URL."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
