from datetime import datetime, timezone
from ipaddress import ip_address
from socket import getaddrinfo
from urllib.parse import urlparse
import requests

from .base import SourceAdapter
from ..models import Artifact

MAX_REMOTE_BYTES = 2 * 1024 * 1024
ALLOWED_PORTS = {None, 80, 443}


def _public_host_only(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise ValueError('Only http/https public URLs are allowed')
    if parsed.port not in ALLOWED_PORTS:
        raise ValueError('Only ports 80/443 are allowed')
    for item in getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80)):
        ip = ip_address(item[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise ValueError('Private/local network targets are not allowed')


class PublicURLSource(SourceAdapter):
    channel = 'public-url'

    def __init__(self, url: str):
        self.url = url

    def collect(self):
        _public_host_only(self.url)
        r = requests.get(self.url, timeout=10, allow_redirects=False, stream=True,
                         headers={'User-Agent': 'CloudLeak-Sentinel/0.5 defensive-scanner'})
        r.raise_for_status()
        ctype = r.headers.get('content-type', '')
        if not any(x in ctype.lower() for x in ('text/', 'json', 'xml', 'yaml', 'javascript')):
            raise ValueError(f'Unsupported remote content type: {ctype or "unknown"}')
        data = bytearray()
        for chunk in r.iter_content(65536):
            data.extend(chunk)
            if len(data) > MAX_REMOTE_BYTES:
                raise ValueError('Remote document exceeds 2 MiB limit')
        text = bytes(data).decode(r.encoding or 'utf-8', errors='ignore')
        now = datetime.now(timezone.utc).isoformat()
        published = r.headers.get('last-modified')
        yield Artifact(source='public-url', channel='public-url', locator=self.url, content=text,
                       observed_at=now, published_at=published)
