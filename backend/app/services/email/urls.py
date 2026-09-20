import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit, urlunsplit
from app.services.email.models import ExtractedDomain, ExtractedURL

# Regex for URL detection in plain text
URL_REGEX = re.compile(
    r'(?:https?://|www\.)[a-zA-Z0-9][-a-zA-Z0-9@:%._+~#=]{0,256}'
    r'\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)',
    re.IGNORECASE
)


class SafeHTMLLinkExtractor(HTMLParser):
    """
    Safely parses HTML markup to extract href and src attributes without network or script execution.
    """
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []  # (url, source_type)

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = dict(attrs)
        if tag.lower() == 'a' and 'href' in attr_dict and attr_dict['href']:
            href = attr_dict['href'].strip()
            if href.startswith(('http://', 'https://', 'www.', '//')):
                self.links.append((href, 'html_anchor'))
        elif tag.lower() in ('img', 'iframe', 'script', 'form') and 'src' in attr_dict and attr_dict['src']:
            src = attr_dict['src'].strip()
            if src.startswith(('http://', 'https://', 'www.', '//')):
                self.links.append((src, f'html_{tag.lower()}_src'))
        elif tag.lower() == 'form' and 'action' in attr_dict and attr_dict['action']:
            action = attr_dict['action'].strip()
            if action.startswith(('http://', 'https://', 'www.', '//')):
                self.links.append((action, 'html_form_action'))


def normalize_url(raw_url: str) -> Tuple[str, str, str, Optional[int], str, str]:
    """
    Normalizes a URL string into components:
    returns (normalized_url, scheme, domain, port, path, query)
    """
    clean_url = raw_url.strip()
    if clean_url.startswith('//'):
        clean_url = 'https:' + clean_url
    elif clean_url.startswith('www.'):
        clean_url = 'http://' + clean_url

    parsed = urlsplit(clean_url)
    scheme = parsed.scheme.lower() if parsed.scheme else 'http'
    hostname = (parsed.hostname or '').lower()
    port = parsed.port
    path = parsed.path or '/'
    query = parsed.query

    # Reconstruct normalized URL
    netloc = hostname
    if port and ((scheme == 'http' and port != 80) or (scheme == 'https' and port != 443)):
        netloc = f"{hostname}:{port}"

    normalized_url = urlunsplit((scheme, netloc, path, query, ''))

    return normalized_url, scheme, hostname, port, path, query


def extract_urls_and_domains(
    plain_text_body: str,
    html_body: Optional[str] = None
) -> Tuple[List[ExtractedURL], List[ExtractedDomain]]:
    """
    Safely extracts all URLs and corresponding domains from plaintext and HTML parts.
    Performs URL normalization and domain aggregation with zero network requests.
    """
    extracted_urls: List[ExtractedURL] = []
    seen_normalized_urls: Set[str] = set()
    domain_map: Dict[str, Dict] = {}  # domain -> { 'urls': set(), 'count': int }

    # 1. Extract from plain text body
    if plain_text_body:
        matches = URL_REGEX.findall(plain_text_body)
        for raw_url in matches:
            norm_url, scheme, domain, port, path, query = normalize_url(raw_url)
            if not domain:
                continue

            if norm_url not in seen_normalized_urls:
                seen_normalized_urls.add(norm_url)
                extracted_urls.append(
                    ExtractedURL(
                        url=raw_url,
                        normalized_url=norm_url,
                        scheme=scheme,
                        domain=domain,
                        port=port,
                        path=path,
                        query=query,
                        source="plain_text",
                    )
                )

            # Record domain
            if domain not in domain_map:
                domain_map[domain] = {'urls': set(), 'count': 0}
            domain_map[domain]['urls'].add(norm_url)
            domain_map[domain]['count'] += 1

    # 2. Extract from HTML body
    if html_body:
        parser = SafeHTMLLinkExtractor()
        try:
            parser.feed(html_body)
            for raw_url, source_tag in parser.links:
                norm_url, scheme, domain, port, path, query = normalize_url(raw_url)
                if not domain:
                    continue

                if norm_url not in seen_normalized_urls:
                    seen_normalized_urls.add(norm_url)
                    extracted_urls.append(
                        ExtractedURL(
                            url=raw_url,
                            normalized_url=norm_url,
                            scheme=scheme,
                            domain=domain,
                            port=port,
                            path=path,
                            query=query,
                            source=source_tag,
                        )
                    )

                # Record domain
                if domain not in domain_map:
                    domain_map[domain] = {'urls': set(), 'count': 0}
                domain_map[domain]['urls'].add(norm_url)
                domain_map[domain]['count'] += 1
        except Exception:
            # Continue gracefully if HTML is malformed
            pass

    # 3. Construct domain summaries
    extracted_domains: List[ExtractedDomain] = [
        ExtractedDomain(
            domain=dom,
            source_urls=list(data['urls']),
            occurrence_count=data['count'],
        )
        for dom, data in sorted(domain_map.items(), key=lambda item: item[1]['count'], reverse=True)
    ]

    return extracted_urls, extracted_domains
