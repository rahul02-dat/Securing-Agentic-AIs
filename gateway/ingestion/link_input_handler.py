import re
import urllib.parse
from typing import List, Optional, Dict, Tuple
from dataclasses import dataclass, field
from gateway.shared.location_tracker import LocationTracker
from gateway.shared.schemas import ContentChannel


@dataclass
class ExtractedContentWithLocation:
    """Container for content with detailed location information."""
    content: str
    channel: ContentChannel
    tag_name: Optional[str] = None
    tag_id: Optional[str] = None
    tag_class: Optional[str] = None
    attribute_name: Optional[str] = None
    css_style: Optional[str] = None
    parent_tag: Optional[str] = None
    line_number: Optional[int] = None


@dataclass
class ExtractedContent:
    """Container for all extracted content from a source."""
    visible_text: str
    hidden_elements: List[str]
    metadata: dict
    raw_html: Optional[str] = None
    location_map: Dict[str, Dict] = field(default_factory=dict)  # Maps content to location info


class LinkInputHandler:
    """
    Handles URL and text input, extracts visible and hidden content with location tracking.
    Tracks DOM positions, CSS hiding techniques, and element metadata.
    """
    
    def __init__(self):
        self.suspicious_patterns = [
            (r'<\s*script[^>]*>.*?</\s*script\s*>', "script"),
            (r'<\s*iframe[^>]*>.*?</\s*iframe\s*>', "iframe"),
            (r'style\s*=\s*["\'].*?display\s*:\s*none', "css_hidden_style"),
            (r'style\s*=\s*["\'].*?visibility\s*:\s*hidden', "css_hidden_visibility"),
            (r'<!--.*?-->', "html_comment"),
            (r'<\s*noscript[^>]*>.*?</\s*noscript\s*>', "noscript"),
        ]
        
        # Patterns for CSS-based hiding
        self.css_hiding_patterns = [
            r'opacity\s*:\s*0',
            r'display\s*:\s*none',
            r'visibility\s*:\s*hidden',
            r'height\s*:\s*0',
            r'width\s*:\s*0',
            r'font-size\s*:\s*0',
            r'text-indent\s*:\s*-?[0-9]+',
            r'clip\s*:\s*rect\(0',
            r'position\s*:\s*absolute.*?(left|right|top|bottom)\s*:\s*-',
            r'color\s*:\s*transparent',
            r'background-color\s*:\s*transparent',
        ]
    
    def process_input(self, input_data: str, input_type: str = "auto") -> ExtractedContent:
        """Process URL or raw text and extract content with location tracking."""
        
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
        """Fetch and extract content from URL with location tracking."""
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
            hidden_elements, location_map = self._extract_hidden_content_with_locations(html_content, soup)
            metadata = self._extract_metadata(soup, url)
            
            return ExtractedContent(
                visible_text=visible_text,
                hidden_elements=hidden_elements,
                metadata=metadata,
                raw_html=html_content,
                location_map=location_map
            )
            
        except Exception as e:
            return ExtractedContent(
                visible_text="",
                hidden_elements=[],
                metadata={"error": str(e), "source": url},
                raw_html=None,
                location_map={}
            )
    
    def _process_text(self, text: str) -> ExtractedContent:
        """Process raw text input with location tracking."""
        
        if self._contains_html(text):
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, 'html.parser')
            visible_text = self._extract_visible_text(soup)
            hidden_elements, location_map = self._extract_hidden_content_with_locations(text, soup)
            metadata = {"input_type": "html_text"}
            raw_html = text
        else:
            visible_text = text
            hidden_elements = []
            location_map = {}
            metadata = {"input_type": "plain_text"}
            raw_html = None
        
        return ExtractedContent(
            visible_text=visible_text,
            hidden_elements=hidden_elements,
            metadata=metadata,
            raw_html=raw_html,
            location_map=location_map
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
    
    def _extract_hidden_content_with_locations(self, html: str, soup) -> Tuple[List[str], Dict[str, Dict]]:
        """
        Extract hidden elements with precise location tracking.
        
        Returns:
            Tuple of (hidden_elements_list, location_metadata_dict)
        """
        hidden = []
        location_map = {}
        element_counter = 0
        
        # Extract from suspicious patterns with location info
        for pattern, pattern_type in self.suspicious_patterns:
            matches = re.finditer(pattern, html, re.DOTALL | re.IGNORECASE)
            for match in matches:
                content = match.group(0)
                hidden.append(content)
                
                # Track location info
                line_number = html[:match.start()].count('\n') + 1
                location_map[f"hidden_{element_counter}"] = {
                    "channel": pattern_type,
                    "pattern_type": pattern_type,
                    "line_number": line_number,
                    "offset": match.start(),
                    "length": len(content)
                }
                element_counter += 1
        
        # Check all elements with style attributes for CSS-based hiding
        all_elements_with_styles = soup.find_all(style=True)
        for element in all_elements_with_styles:
            style = element.get('style', '')
            normalized_style = style.replace(' ', '').lower()
            
            # Check each hiding pattern
            is_hidden = False
            hiding_technique = None
            for hiding_pattern in self.css_hiding_patterns:
                if re.search(hiding_pattern, normalized_style, re.IGNORECASE):
                    is_hidden = True
                    hiding_technique = hiding_pattern
                    break
            
            if is_hidden:
                content = str(element)
                hidden.append(content)
                
                # Find position in original HTML
                if element.name:
                    line_number = str(element).count('\n')
                    location_map[f"hidden_{element_counter}"] = {
                        "channel": "css_hidden",
                        "tag_name": element.name,
                        "tag_id": element.get('id'),
                        "tag_class": element.get('class'),
                        "css_style": style,
                        "hiding_technique": hiding_technique,
                        "text_preview": element.get_text()[:100]
                    }
                    element_counter += 1
        
        # Check for elements with hidden classes
        for element in soup.find_all(class_=True):
            classes = element.get('class', [])
            if any('hidden' in c.lower() for c in classes):
                content = str(element)
                hidden.append(content)
                
                location_map[f"hidden_{element_counter}"] = {
                    "channel": "css_class_hidden",
                    "tag_name": element.name,
                    "tag_id": element.get('id'),
                    "tag_class": ' '.join(classes),
                    "text_preview": element.get_text()[:100]
                }
                element_counter += 1
        
        # Extract HTML comments with location
        for comment_match in re.finditer(r'<!--(.*?)-->', html, re.DOTALL):
            content = comment_match.group(0)
            hidden.append(content)
            
            line_number = html[:comment_match.start()].count('\n') + 1
            location_map[f"hidden_{element_counter}"] = {
                "channel": "html_comment",
                "line_number": line_number,
                "offset": comment_match.start(),
                "text_preview": content[4:-3][:100]  # Remove <!-- and -->
            }
            element_counter += 1
        
        # Check for zero-size elements
        zero_size_elements = soup.find_all(style=re.compile(r'(width|height)\s*:\s*0', re.IGNORECASE))
        for element in zero_size_elements:
            if element not in all_elements_with_styles:  # Avoid duplicates
                content = str(element)
                hidden.append(content)
                
                location_map[f"hidden_{element_counter}"] = {
                    "channel": "zero_size_element",
                    "tag_name": element.name,
                    "css_style": element.get('style'),
                    "text_preview": element.get_text()[:100]
                }
                element_counter += 1
        
        # Check for overflow hidden with text-indent or other text-hiding techniques
        for element in soup.find_all():
            style = element.get('style', '')
            if style:
                normalized = style.replace(' ', '').lower()
                # Look for text-indent with large negative values
                if re.search(r'text-indent\s*:\s*-\d+', normalized):
                    content = str(element)
                    if content not in hidden:
                        hidden.append(content)
                        location_map[f"hidden_{element_counter}"] = {
                            "channel": "text_indent_hidden",
                            "tag_name": element.name,
                            "css_style": style,
                            "text_preview": element.get_text()[:100]
                        }
                        element_counter += 1
                
                # Look for position absolute with negative offsets
                if (re.search(r'position\s*:\s*absolute', normalized) and 
                    re.search(r'(left|right|top|bottom)\s*:\s*-\d+', normalized)):
                    content = str(element)
                    if content not in hidden:
                        hidden.append(content)
                        location_map[f"hidden_{element_counter}"] = {
                            "channel": "absolute_position_hidden",
                            "tag_name": element.name,
                            "css_style": style,
                            "text_preview": element.get_text()[:100]
                        }
                        element_counter += 1
        
        return hidden, location_map
    
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
