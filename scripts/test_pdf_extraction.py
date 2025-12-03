#!/usr/bin/env python3
"""Unit tests for PDF extraction parsing helpers.

This module provides lightweight tests for the text processing functions
used in the PDF extraction script. These tests use doctest format for
simplicity and can be run without the full book PDF.
"""
import doctest
import sys
from pathlib import Path

# Add the scripts directory to the path so we can import the module
sys.path.insert(0, str(Path(__file__).parent))

# Import the functions we want to test
try:
    from extract_practical_cyber_intel import (
        is_chapter_heading,
        is_section_heading,
        extract_chapter_title,
        extract_section_title,
        parse_content_hierarchy,
        CHAPTER_PATTERNS,
        SECTION_PATTERNS
    )
except ImportError as e:
    print(f"Could not import extraction functions: {e}")
    sys.exit(1)


def test_chapter_detection():
    """Test chapter heading detection."""
    # Test cases for chapter detection
    test_cases = [
        ("Chapter 1: Introduction to Cyber Intelligence", True),
        ("Chapter 2 - Threat Intelligence Fundamentals", True),
        ("1 Getting Started with Intelligence", True),
        ("CHAPTER 3: Advanced Analysis Techniques", True),
        ("Some regular text content", False),
        ("1.2 This is a section, not a chapter", False),
        ("Introduction", False),
    ]
    
    for text, expected in test_cases:
        result = is_chapter_heading(text)
        assert result == expected, f"Failed for '{text}': expected {expected}, got {result}"
    
    print("✓ Chapter detection tests passed")


def test_section_detection():
    """Test section heading detection."""
    test_cases = [
        ("1.1 Introduction", True),
        ("2.3.4 Advanced Topics", True),
        ("Methodology:", True),
        ("Regular paragraph text", False),
        ("Chapter 1: Title", False),
        ("1 Getting Started", False),  # This looks like a chapter
    ]
    
    for text, expected in test_cases:
        result = is_section_heading(text)
        assert result == expected, f"Failed for '{text}': expected {expected}, got {result}"
    
    print("✓ Section detection tests passed")


def test_title_extraction():
    """Test title extraction from headings."""
    # Chapter title extraction
    chapter_cases = [
        ("Chapter 1: Introduction to Cyber Intelligence", "Introduction to Cyber Intelligence"),
        ("Chapter 2 - Threat Intelligence Fundamentals", "Threat Intelligence Fundamentals"),
        ("1 Getting Started with Intelligence", "Getting Started with Intelligence"),
        ("CHAPTER 3: Advanced Analysis Techniques", "Advanced Analysis Techniques"),
    ]
    
    for text, expected in chapter_cases:
        result = extract_chapter_title(text)
        assert result == expected, f"Failed chapter extraction for '{text}': expected '{expected}', got '{result}'"
    
    # Section title extraction
    section_cases = [
        ("1.1 Introduction", "Introduction"),
        ("2.3.4 Advanced Topics", "Advanced Topics"),
        ("Methodology:", "Methodology"),
    ]
    
    for text, expected in section_cases:
        result = extract_section_title(text)
        assert result == expected, f"Failed section extraction for '{text}': expected '{expected}', got '{result}'"
    
    print("✓ Title extraction tests passed")


def test_content_hierarchy_parsing():
    """Test content hierarchy parsing with sample data."""
    # Sample page content simulating extracted text
    sample_pages = [
        (1, "Chapter 1: Introduction\nThis is the first chapter."),
        (2, "1.1 Getting Started\nThis is the first section.\nMore content here."),
        (3, "1.2 Basic Concepts\nThis is the second section.\nAdditional details."),
        (4, "Chapter 2: Advanced Topics\nThis is the second chapter."),
        (5, "2.1 Complex Analysis\nAdvanced section content."),
    ]
    
    result = parse_content_hierarchy(sample_pages)
    
    # Verify structure
    assert len(result.chapters) == 2, f"Expected 2 chapters, got {len(result.chapters)}"
    
    # First chapter
    chapter1 = result.chapters[0]
    assert chapter1.title == "Introduction", f"Expected 'Introduction', got '{chapter1.title}'"
    assert len(chapter1.sections) == 2, f"Expected 2 sections in chapter 1, got {len(chapter1.sections)}"
    
    # Second chapter
    chapter2 = result.chapters[1]
    assert chapter2.title == "Advanced Topics", f"Expected 'Advanced Topics', got '{chapter2.title}'"
    assert len(chapter2.sections) == 1, f"Expected 1 section in chapter 2, got {len(chapter2.sections)}"
    
    print("✓ Content hierarchy parsing tests passed")


def test_edge_cases():
    """Test edge cases and error conditions."""
    # Empty content
    empty_result = parse_content_hierarchy([])
    assert len(empty_result.chapters) == 0, "Empty input should produce no chapters"
    
    # Content without chapter structure
    flat_pages = [
        (1, "Just some regular text content."),
        (2, "More text without structure."),
        (3, "Final page of content."),
    ]
    
    flat_result = parse_content_hierarchy(flat_pages)
    # Should create a single chapter when no structure is detected
    assert len(flat_result.chapters) == 1, "Flat content should create single chapter"
    assert flat_result.chapters[0].title == "Complete Content", "Default chapter title should be 'Complete Content'"
    
    # Invalid chapter patterns
    invalid_chapters = [
        ("Not a chapter", False),
        ("", False),
        ("123", False),  # Just numbers, no title
        ("Chapter:", False),  # Chapter with no number
    ]
    
    for text, expected in invalid_chapters:
        result = is_chapter_heading(text)
        assert result == expected, f"Failed invalid chapter test for '{text}': expected {expected}, got {result}"
    
    print("✓ Edge case tests passed")


def run_doctests():
    """Run doctests if any exist."""
    # This will run any doctests in the module
    doctest.testmod(verbose=False)
    print("✓ Doctests completed")


def main():
    """Run all tests."""
    print("Running PDF extraction parsing helper tests...")
    print("=" * 50)
    
    try:
        test_chapter_detection()
        test_section_detection()
        test_title_extraction()
        test_content_hierarchy_parsing()
        test_edge_cases()
        run_doctests()
        
        print("=" * 50)
        print("✓ All tests passed!")
        return 0
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())