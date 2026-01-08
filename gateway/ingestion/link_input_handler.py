import re
import urllib.parse
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class ExtractedContent:
    """Container for all extracted content from a source."""
    visible_text: str
    hidden_elements: List[str]
    metadata: dict
    raw_html: Optional[str] = None


class LinkInputHandler:
    """Handles URL and text input, extracts visible and hidden content."""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'<\s*script[^>]*>.*?</\s*script\s*>',
            r'<\s*iframe[^>]*>.*?</\s*iframe\s*>',
            r'style\s*=\s*["\'].*?display\s*:\s*none',
            r'style\s*=\s*["\'].*?visibility\s*:\s*hidden',
            r'<!--.*?-->',
            r'<\s*noscript[^>]*>.*?</\s*noscript\s*>',
        ]
    
    def process_input(self, input_data: str, input_type: str = "auto") -> ExtractedContent:
        """Process URL or raw text and extract content."""
        
        detected_type = self._detect_input_type(input_data) if input_type == "auto" else input_type
        
        if detected_type == "url":
            return self._process_url(input_data)
        else:
            return self._process_text(input_data)
    
    def _detect_input_type(self, input_data: str) -> str:
        """Determine if input is URL or raw text."""
        url_pattern = r'^https?://'
        if re.match(url_pattern, input_data.strip()):
            return "url"
        return "text"
    
    def _process_url(self, url: str) -> ExtractedContent:
        """Fetch and extract content from URL."""
        try:
            import requests
            from bs4 import BeautifulSoup
            
            response = requests.get(url, timeout=10, headers={
                'User-Agent': 'UnseenLinkGuard/1.0 Security Scanner'
            })
            response.raise_for_status()
            
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            visible_text = self._extract_visible_text(soup)
            hidden_elements = self._extract_hidden_content(html_content, soup)
            metadata = self._extract_metadata(soup, url)
            
            return ExtractedContent(
                visible_text=visible_text,
                hidden_elements=hidden_elements,
                metadata=metadata,
                raw_html=html_content
            )
            
        except Exception as e:
            return ExtractedContent(
                visible_text="",
                hidden_elements=[],
                metadata={"error": str(e), "source": url},
                raw_html=None
            )
    
    def _process_text(self, text: str) -> ExtractedContent:
        """Process raw text input."""
        
        if self._contains_html(text):
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, 'html.parser')
            visible_text = self._extract_visible_text(soup)
            hidden_elements = self._extract_hidden_content(text, soup)
            metadata = {"input_type": "html_text"}
            raw_html = text
        else:
            visible_text = text
            hidden_elements = []
            metadata = {"input_type": "plain_text"}
            raw_html = None
        
        return ExtractedContent(
            visible_text=visible_text,
            hidden_elements=hidden_elements,
            metadata=metadata,
            raw_html=raw_html
        )
    
    def _contains_html(self, text: str) -> bool:
        """Check if text contains HTML tags."""
        html_pattern = r'<[^>]+>'
        return bool(re.search(html_pattern, text))
    
    def _extract_visible_text(self, soup) -> str:
        """Extract visible text from BeautifulSoup object."""
        for script in soup(["script", "style", "noscript"]):
            script.decompose()
        
        text = soup.get_text(separator=' ', strip=True)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def _extract_hidden_content(self, html: str, soup) -> List[str]:
        """Extract hidden elements, comments, and obfuscated content."""
        hidden = []
        
        for pattern in self.suspicious_patterns:
            matches = re.findall(pattern, html, re.DOTALL | re.IGNORECASE)
            hidden.extend(matches)
        
        for element in soup.find_all(style=True):
            style = element.get('style', '')
            if 'display:none' in style.replace(' ', '') or 'visibility:hidden' in style.replace(' ', ''):
                hidden.append(str(element))
        
        for element in soup.find_all(class_=True):
            classes = element.get('class', [])
            if any('hidden' in c.lower() for c in classes):
                hidden.append(str(element))
        
        comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
        hidden.extend([str(c) for c in comments])
        
        zero_size_elements = soup.find_all(style=re.compile(r'(width|height)\s*:\s*0'))
        hidden.extend([str(e) for e in zero_size_elements])
        
        return hidden
    
    def _extract_metadata(self, soup, url: str) -> dict:
        """Extract metadata from HTML."""
        metadata = {
            "source_url": url,
            "title": soup.title.string if soup.title else None,
        }
        
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            name = tag.get('name') or tag.get('property')
            content = tag.get('content')
            if name and content:
                metadata[name] = content
        
        parsed_url = urllib.parse.urlparse(url)
        metadata["domain"] = parsed_url.netloc
        metadata["scheme"] = parsed_url.scheme
        
        return metadata