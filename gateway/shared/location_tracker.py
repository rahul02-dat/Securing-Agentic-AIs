"""
Location tracking utilities for identifying where prompt injections occur.

Provides location tracking across multiple formats:
- Text: line numbers and offsets
- HTML: DOM tags, attributes, CSS styles
- PDF: page numbers and block positions
- Images: OCR bounding boxes
"""

from typing import Optional, List, Dict, Tuple
from gateway.shared.schemas import LocationReference, ContentChannel


class LocationTracker:
    """Tracks location information during content parsing."""
    
    @staticmethod
    def track_text_location(
        text: str,
        start_offset: int,
        end_offset: int,
        channel: ContentChannel = ContentChannel.VISIBLE,
        context_chars: int = 50
    ) -> LocationReference:
        """
        Track location in plain text using line numbers and offsets.
        
        Args:
            text: Full text content
            start_offset: Start position in text
            end_offset: End position in text
            channel: Content channel (visible, hidden, etc)
            context_chars: Number of chars to include before/after
            
        Returns:
            LocationReference with line and offset information
        """
        line_number = text[:start_offset].count('\n') + 1
        
        # Find line start
        line_start = text.rfind('\n', 0, start_offset) + 1
        
        # Calculate offset within line
        line_offset = start_offset - line_start
        
        # Get context
        context_start = max(0, start_offset - context_chars)
        context_end = min(len(text), end_offset + context_chars)
        
        context_before = text[context_start:start_offset].strip()[-20:] if start_offset > 0 else None
        context_after = text[end_offset:context_end].strip()[:20] if end_offset < len(text) else None
        
        return LocationReference(
            channel=channel,
            line_number=line_number,
            offset=start_offset,
            context_before=context_before,
            context_after=context_after
        )
    
    @staticmethod
    def track_html_location(
        element_tag: str,
        element_id: Optional[str] = None,
        element_class: Optional[str] = None,
        attribute_name: Optional[str] = None,
        parent_tag: Optional[str] = None,
        css_style: Optional[str] = None,
        channel: ContentChannel = ContentChannel.HIDDEN
    ) -> LocationReference:
        """
        Track location in HTML DOM structure.
        
        Args:
            element_tag: HTML tag name (div, span, script, etc)
            element_id: HTML id attribute
            element_class: HTML class attribute
            attribute_name: Specific attribute being analyzed
            parent_tag: Parent element tag
            css_style: CSS style attribute value
            channel: Content channel
            
        Returns:
            LocationReference with DOM information
        """
        return LocationReference(
            channel=channel,
            tag_name=element_tag,
            tag_id=element_id,
            tag_class=element_class,
            attribute_name=attribute_name,
            parent_tag=parent_tag,
            css_style=css_style
        )
    
    @staticmethod
    def track_pdf_location(
        page_number: int,
        block_index: Optional[int] = None,
        bbox: Optional[Dict[str, float]] = None
    ) -> LocationReference:
        """
        Track location in PDF document.
        
        Args:
            page_number: Page number (1-indexed)
            block_index: Block/paragraph index on page
            bbox: Bounding box {x, y, width, height}
            
        Returns:
            LocationReference with PDF information
        """
        return LocationReference(
            channel=ContentChannel.VISIBLE,
            page_number=page_number,
            bbox=bbox
        )
    
    @staticmethod
    def track_ocr_location(
        bbox: Dict[str, float],
        page_number: int = 1
    ) -> LocationReference:
        """
        Track location in OCR-extracted text with bounding box.
        
        Args:
            bbox: Bounding box from OCR {x, y, width, height}
            page_number: Page number for multi-page images
            
        Returns:
            LocationReference with OCR information
        """
        return LocationReference(
            channel=ContentChannel.OCR,
            page_number=page_number,
            bbox=bbox
        )
    
    @staticmethod
    def track_encoded_location(
        original_encoding: str,
        decoded_text: str,
        decoded_offset: int,
        channel: ContentChannel = ContentChannel.ENCODED
    ) -> LocationReference:
        """
        Track location of encoded content with decoding trace.
        
        Args:
            original_encoding: Type of encoding (html_entity, unicode, base64, etc)
            decoded_text: The decoded content
            decoded_offset: Offset in decoded text
            channel: Content channel
            
        Returns:
            LocationReference for encoded content
        """
        return LocationReference(
            channel=channel,
            offset=decoded_offset
        )
    
    @staticmethod
    def find_pattern_locations(
        text: str,
        pattern_matches: List[Tuple[int, int, str]],
        channel: ContentChannel = ContentChannel.VISIBLE,
        context_chars: int = 50
    ) -> List[LocationReference]:
        """
        Find all locations where a pattern matches in text.
        
        Args:
            text: Full text content
            pattern_matches: List of (start, end, matched_text) tuples
            channel: Content channel
            context_chars: Context window size
            
        Returns:
            List of LocationReference objects for each match
        """
        locations = []
        for start, end, _ in pattern_matches:
            loc = LocationTracker.track_text_location(
                text, start, end, channel, context_chars
            )
            locations.append(loc)
        return locations


class EncodingTracer:
    """Tracks encoding/decoding transformations for traceability."""
    
    def __init__(self):
        self.trace: List[Dict[str, str]] = []
    
    def add_step(self, encoding_type: str, input_snippet: str, output_snippet: str) -> None:
        """
        Record an encoding/decoding step.
        
        Args:
            encoding_type: Type of encoding (html_entity, unicode, base64, etc)
            input_snippet: Input to this step
            output_snippet: Output from this step
        """
        self.trace.append({
            "encoding": encoding_type,
            "input": input_snippet[:100],  # Truncate for readability
            "output": output_snippet[:100]
        })
    
    def get_trace(self) -> List[str]:
        """Get simplified encoding trace as list of encoding types."""
        return [step["encoding"] for step in self.trace]
    
    def get_detailed_trace(self) -> List[Dict[str, str]]:
        """Get detailed encoding trace."""
        return self.trace
    
    def has_encoding(self) -> bool:
        """Check if any encoding was detected."""
        return len(self.trace) > 0


class ContentRegion:
    """Represents a region of content with location metadata."""
    
    def __init__(self, content: str, channel: ContentChannel, location: LocationReference):
        self.content = content
        self.channel = channel
        self.location = location
    
    def get_snippet(self, max_length: int = 100) -> str:
        """Get truncated content snippet."""
        if len(self.content) > max_length:
            return self.content[:max_length] + "..."
        return self.content
