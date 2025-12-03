#!/usr/bin/env python3
"""Extract content from Practical Cyber Intelligence PDF book.

This script provides a robust PDF ingestion pipeline with:
1. Text-first extraction using PyPDF2
2. OCR fallback for pages with insufficient text using pdf2image + pytesseract
3. Structured JSON output preserving chapter → section → paragraph hierarchy
4. Raw text transcript for manual inspection
5. Dependency validation with actionable error messages

Usage:
    python3 scripts/extract_practical_cyber_intel.py --pdf ./Practical*.pdf --output data/source_material/practical_cyber_intelligence

Requirements:
    - Python packages listed in scripts/requirements.txt
    - System dependencies: Tesseract OCR, Poppler utilities
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import subprocess

# Try to import required packages with helpful error messages
try:
    import PyPDF2
except ImportError as e:
    print("ERROR: PyPDF2 is required. Install with: pip install PyPDF2", file=sys.stderr)
    sys.exit(1)

try:
    from pdf2image import convert_from_path
except ImportError as e:
    print("ERROR: pdf2image is required. Install with: pip install pdf2image", file=sys.stderr)
    sys.exit(1)

try:
    import pytesseract
except ImportError as e:
    print("ERROR: pytesseract is required. Install with: pip install pytesseract", file=sys.stderr)
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Constants
MIN_TEXT_LENGTH = 100  # Minimum characters to consider text extraction successful
OCR_DPI = 300  # DPI for OCR image conversion
CHAPTER_PATTERNS = [
    r'^Chapter\s+\d+[:\s-]+(.+)$',
    r'^\d+\s+(.+?)\s*$',
    r'^CHAPTER\s+\d+[:\s-]+(.+)$',
]

SECTION_PATTERNS = [
    r'^\d+\.\d+\s+(.+)$',
    r'^\d+\.\d+\.\d+\s+(.+)$',
    r'^([A-Z][a-z\s]+):$',
]


@dataclass
class Paragraph:
    """Represents a paragraph with page context."""
    text: str
    page_number: int
    is_heading: bool = False


@dataclass
class Section:
    """Represents a section within a chapter."""
    title: str
    paragraphs: List[Paragraph]
    page_number: int


@dataclass
class Chapter:
    """Represents a book chapter."""
    title: str
    sections: List[Section]
    page_number: int


@dataclass
class BookContent:
    """Complete structured book content."""
    title: str
    chapters: List[Chapter]
    raw_text: str
    extraction_stats: Dict[str, Any]


def check_system_dependencies() -> bool:
    """Check if Tesseract and Poppler are available."""
    try:
        subprocess.run(['tesseract', '--version'], capture_output=True, check=True)
        logger.info("✓ Tesseract OCR found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("✗ Tesseract OCR not found")
        logger.error("Install Tesseract OCR:")
        logger.error("  Ubuntu/Debian: sudo apt install tesseract-ocr")
        logger.error("  macOS: brew install tesseract")
        logger.error("  Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki")
        return False

    try:
        subprocess.run(['pdftoppm', '-v'], capture_output=True, check=True)
        logger.info("✓ Poppler utilities found")
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.error("✗ Poppler utilities not found")
        logger.error("Install Poppler utilities:")
        logger.error("  Ubuntu/Debian: sudo apt install poppler-utils")
        logger.error("  macOS: brew install poppler")
        logger.error("  Windows: Download from http://blog.alivate.com.au/poppler-windows/")
        return False

    return True


def extract_text_from_page(page) -> str:
    """Extract text from a PDF page using PyPDF2."""
    try:
        text = page.extract_text()
        return text.strip() if text else ""
    except Exception as e:
        logger.warning(f"Error extracting text from page: {e}")
        return ""


def ocr_page(page_image) -> str:
    """Perform OCR on a page image using Tesseract."""
    try:
        text = pytesseract.image_to_string(page_image, config='--psm 6')
        return text.strip() if text else ""
    except Exception as e:
        logger.warning(f"Error performing OCR on page: {e}")
        return ""


def is_chapter_heading(text: str) -> bool:
    """Check if text matches chapter heading patterns."""
    for pattern in CHAPTER_PATTERNS:
        if re.match(pattern, text.strip(), re.IGNORECASE | re.MULTILINE):
            return True
    return False


def is_section_heading(text: str) -> bool:
    """Check if text matches section heading patterns."""
    for pattern in SECTION_PATTERNS:
        if re.match(pattern, text.strip(), re.IGNORECASE | re.MULTILINE):
            return True
    return False


def extract_chapter_title(text: str) -> Optional[str]:
    """Extract chapter title from heading text."""
    for pattern in CHAPTER_PATTERNS:
        match = re.match(pattern, text.strip(), re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    return None


def extract_section_title(text: str) -> Optional[str]:
    """Extract section title from heading text."""
    for pattern in SECTION_PATTERNS:
        match = re.match(pattern, text.strip(), re.IGNORECASE | re.MULTILINE)
        if match:
            return match.group(1).strip()
    return None


def parse_content_hierarchy(pages_text: List[Tuple[int, str]]) -> BookContent:
    """Parse flat text into structured chapter → section → paragraph hierarchy."""
    chapters: List[Chapter] = []
    current_chapter: Optional[Chapter] = None
    current_section: Optional[Section] = None
    raw_text_parts = []
    ocr_pages = 0
    text_pages = 0

    for page_num, text in pages_text:
        raw_text_parts.append(f"--- Page {page_num} ---\n{text}\n")
        
        if not text.strip():
            continue

        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Check for chapter heading
            if is_chapter_heading(line):
                chapter_title = extract_chapter_title(line)
                if chapter_title:
                    # Save previous chapter
                    if current_chapter:
                        if current_section and current_section.paragraphs:
                            current_chapter.sections.append(current_section)
                        chapters.append(current_chapter)
                    
                    # Start new chapter
                    current_chapter = Chapter(
                        title=chapter_title,
                        sections=[],
                        page_number=page_num
                    )
                    current_section = None
                continue

            # Check for section heading
            if is_section_heading(line) and current_chapter:
                section_title = extract_section_title(line)
                if section_title:
                    # Save previous section
                    if current_section and current_section.paragraphs:
                        current_chapter.sections.append(current_section)
                    
                    # Start new section
                    current_section = Section(
                        title=section_title,
                        paragraphs=[],
                        page_number=page_num
                    )
                continue

            # Regular paragraph
            if current_chapter:
                if not current_section:
                    # Create default section if none exists, but skip very short lines
                    # that are likely chapter introductions
                    if len(line) > 50:  # Only create section for substantial content
                        current_section = Section(
                            title="Introduction",
                            paragraphs=[],
                            page_number=page_num
                        )
                
                # Add paragraph only if we have a section
                if current_section:
                    current_section.paragraphs.append(
                        Paragraph(
                            text=line,
                            page_number=page_num,
                            is_heading=False
                        )
                    )

    # Save final chapter and section
    if current_chapter:
        if current_section and current_section.paragraphs:
            current_chapter.sections.append(current_section)
        chapters.append(current_chapter)

    # If no chapters were detected, create a single chapter with all content
    if not chapters and pages_text:
        logger.warning("No chapter structure detected, creating single chapter")
        all_paragraphs = []
        for page_num, text in pages_text:
            if text.strip():
                for line in text.strip().split('\n'):
                    line = line.strip()
                    if line:
                        all_paragraphs.append(
                            Paragraph(text=line, page_number=page_num)
                        )
        
        complete_chapter = Chapter(
            title="Complete Content",
            sections=[
                Section(
                    title="Full Text",
                    paragraphs=all_paragraphs,
                    page_number=1
                )
            ],
            page_number=1
        )
        chapters.append(complete_chapter)
        text_pages = len(pages_text)
    else:
        text_pages = len(pages_text) - ocr_pages

    return BookContent(
        title="Practical Cyber Intelligence",
        chapters=chapters,
        raw_text='\n'.join(raw_text_parts),
        extraction_stats={
            "total_pages": len(pages_text),
            "text_extraction_pages": text_pages,
            "ocr_pages": ocr_pages,
            "chapters_detected": len(chapters),
            "total_sections": sum(len(ch.sections) for ch in chapters),
            "total_paragraphs": sum(
                len(section.paragraphs) 
                for chapter in chapters 
                for section in chapter.sections
            )
        }
    )


def extract_pdf_content(pdf_path: Path, page_range: Optional[Tuple[int, int]] = None) -> BookContent:
    """Extract content from PDF with OCR fallback."""
    logger.info(f"Opening PDF: {pdf_path}")
    
    try:
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            total_pages = len(pdf_reader.pages)
            
            # Determine page range
            if page_range:
                start_page, end_page = page_range
                start_page = max(1, start_page)
                end_page = min(total_pages, end_page)
                page_indices = range(start_page - 1, end_page)
            else:
                page_indices = range(total_pages)
            
            logger.info(f"Processing {len(page_indices)} pages (total: {total_pages})")
            
            pages_text = []
            ocr_pages = 0
            text_pages = 0
            
            for i, page_index in enumerate(page_indices):
                page = pdf_reader.pages[page_index]
                page_num = page_index + 1
                
                logger.info(f"Processing page {page_num}/{total_pages}")
                
                # First attempt: text extraction
                text = extract_text_from_page(page)
                
                # Check if text extraction was sufficient
                if len(text) >= MIN_TEXT_LENGTH:
                    pages_text.append((page_num, text))
                    text_pages += 1
                    logger.debug(f"✓ Page {page_num}: Text extraction ({len(text)} chars)")
                else:
                    logger.info(f"⚠ Page {page_num}: Insufficient text ({len(text)} chars), using OCR")
                    
                    # Fallback: OCR
                    try:
                        images = convert_from_path(
                            str(pdf_path),
                            first_page=page_num,
                            last_page=page_num,
                            dpi=OCR_DPI,
                            single_file=True
                        )
                        
                        if images:
                            ocr_text = ocr_page(images[0])
                            if ocr_text:
                                pages_text.append((page_num, ocr_text))
                                ocr_pages += 1
                                logger.info(f"✓ Page {page_num}: OCR extraction ({len(ocr_text)} chars)")
                            else:
                                logger.warning(f"✗ Page {page_num}: OCR failed, using empty text")
                                pages_text.append((page_num, ""))
                        else:
                            logger.warning(f"✗ Page {page_num}: Could not convert to image")
                            pages_text.append((page_num, ""))
                            
                    except Exception as e:
                        logger.error(f"✗ Page {page_num}: OCR error: {e}")
                        pages_text.append((page_num, ""))
            
            logger.info(f"Extraction complete: {text_pages} text pages, {ocr_pages} OCR pages")
            
            # Parse content structure
            return parse_content_hierarchy(pages_text)
            
    except Exception as e:
        logger.error(f"Error processing PDF: {e}")
        raise


def save_output(content: BookContent, output_dir: Path) -> None:
    """Save structured content and raw text to output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save structured JSON
    json_path = output_dir / "structured_book.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(asdict(content), f, indent=2, ensure_ascii=False)
    logger.info(f"✓ Structured JSON saved: {json_path}")
    
    # Save raw text
    raw_path = output_dir / "raw_transcript.txt"
    with open(raw_path, 'w', encoding='utf-8') as f:
        f.write(content.raw_text)
    logger.info(f"✓ Raw transcript saved: {raw_path}")
    
    # Save extraction stats
    stats_path = output_dir / "extraction_stats.json"
    with open(stats_path, 'w', encoding='utf-8') as f:
        json.dump(content.extraction_stats, f, indent=2)
    logger.info(f"✓ Extraction stats saved: {stats_path}")


def parse_page_range(range_str: str) -> Tuple[int, int]:
    """Parse page range string like '1-50' or '10-20'."""
    try:
        start, end = map(int, range_str.split('-'))
        if start <= 0 or end <= 0:
            raise ValueError("Page numbers must be positive")
        if start > end:
            raise ValueError("Start page must be <= end page")
        return start, end
    except ValueError as e:
        raise argparse.ArgumentTypeError(f"Invalid page range '{range_str}': {e}")


def main() -> None:
    """Main extraction function."""
    parser = argparse.ArgumentParser(
        description="Extract content from Practical Cyber Intelligence PDF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Extract entire book
    python3 scripts/extract_practical_cyber_intel.py \\
        --pdf "./Practical Cyber Intelligence.pdf" \\
        --output data/source_material/practical_cyber_intelligence
    
    # Extract specific page range
    python3 scripts/extract_practical_cyber_intel.py \\
        --pdf "./Practical Cyber Intelligence.pdf" \\
        --output data/source_material/practical_cyber_intelligence \\
        --pages 1-50
        """
    )
    
    parser.add_argument(
        '--pdf',
        type=Path,
        required=True,
        help='Path to PDF file'
    )
    
    parser.add_argument(
        '--output',
        type=Path,
        required=True,
        help='Output directory for extracted content'
    )
    
    parser.add_argument(
        '--pages',
        type=parse_page_range,
        help='Page range to extract (e.g., "1-50"). Default: all pages'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate inputs
    if not args.pdf.exists():
        logger.error(f"PDF file not found: {args.pdf}")
        sys.exit(1)
    
    if not args.pdf.is_file():
        logger.error(f"Path is not a file: {args.pdf}")
        sys.exit(1)
    
    if not args.pdf.suffix.lower() == '.pdf':
        logger.error(f"File must have .pdf extension: {args.pdf}")
        sys.exit(1)
    
    # Check system dependencies
    logger.info("Checking system dependencies...")
    if not check_system_dependencies():
        logger.error("Missing system dependencies. Please install them and retry.")
        sys.exit(1)
    
    try:
        # Extract content
        logger.info("Starting PDF extraction...")
        content = extract_pdf_content(args.pdf, args.pages)
        
        # Save output
        logger.info("Saving extracted content...")
        save_output(content, args.output)
        
        # Print summary
        stats = content.extraction_stats
        logger.info("=" * 50)
        logger.info("EXTRACTION SUMMARY")
        logger.info("=" * 50)
        logger.info(f"Total pages processed: {stats['total_pages']}")
        logger.info(f"Text extraction pages: {stats['text_extraction_pages']}")
        logger.info(f"OCR pages: {stats['ocr_pages']}")
        logger.info(f"Chapters detected: {stats['chapters_detected']}")
        logger.info(f"Total sections: {stats['total_sections']}")
        logger.info(f"Total paragraphs: {stats['total_paragraphs']}")
        logger.info("=" * 50)
        logger.info(f"✓ Extraction completed successfully!")
        logger.info(f"📁 Output directory: {args.output}")
        logger.info(f"📄 Structured JSON: {args.output / 'structured_book.json'}")
        logger.info(f"📄 Raw transcript: {args.output / 'raw_transcript.txt'}")
        
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()