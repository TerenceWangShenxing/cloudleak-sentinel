from datetime import datetime, timezone
from html.parser import HTMLParser
import re
import requests

from .base import SourceAdapter
from .url import _public_host_only, MAX_REMOTE_BYTES
from ..models import Artifact


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.skip = 0
    def handle_starttag(self, tag, attrs):
        if tag in {'script','style','svg'}:
            self.skip += 1
        elif tag in {'pre','code','p','div','br','li','td','th','h1','h2','h3','h4'}:
            self.parts.append('\n')
    def handle_endtag(self, tag):
        if tag in {'script','style','svg'} and self.skip:
            self.skip -= 1
        elif tag in {'pre','code','p','div','li','td','th'}:
            self.parts.append('\n')
    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)
    def text(self):
        return re.sub(r'\n{3,}', '\n\n', ''.join(self.parts))


class PublicWikiPageSource(SourceAdapter):
    """Fetch one explicitly supplied public Wiki/knowledge page and normalize visible/code text."""
    channel = 'wiki'

    def __init__(self, url: str):
        self.url = url

    def collect(self):
        _public_host_only(self.url)
        r = requests.get(
            self.url, timeout=10, allow_redirects=False, stream=True,
            headers={'User-Agent': 'CloudLeak-Sentinel/0.5 defensive-scanner'},
        )
        r.raise_for_status()
        ctype = (r.headers.get('content-type') or '').lower()
        if 'html' not in ctype and 'text/' not in ctype:
            raise ValueError(f'Wiki/knowledge page must be text/html: {ctype or "unknown"}')
        data = bytearray()
        for chunk in r.iter_content(65536):
            data.extend(chunk)
            if len(data) > MAX_REMOTE_BYTES:
                raise ValueError('Remote page exceeds 2 MiB limit')
        raw = bytes(data).decode(r.encoding or 'utf-8', errors='ignore')
        if 'html' in ctype or '<html' in raw[:1000].lower():
            parser = _TextExtractor(); parser.feed(raw); text = parser.text()
        else:
            text = raw
        yield Artifact(
            source='public-wiki-page', channel='wiki', locator=self.url, content=text,
            observed_at=datetime.now(timezone.utc).isoformat(), published_at=r.headers.get('last-modified'),
            metadata={'content_type': ctype, 'normalized_html': True},
        )
