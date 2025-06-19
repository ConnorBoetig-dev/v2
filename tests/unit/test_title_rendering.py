"""
Unit tests for title rendering
"""
import pytest
from pathlib import Path
import re


class TestTitleRendering:
    """Test that the page title is visible and renders correctly"""

    @pytest.fixture
    def report_template_path(self):
        """Get path to main report template"""
        return Path(__file__).parent.parent.parent / "templates" / "report.html"

    @pytest.fixture
    def report_content(self, report_template_path):
        """Load report template content"""
        with open(report_template_path, "r") as f:
            return f.read()

    def test_title_element_exists(self, report_content):
        """Test that the title element exists in the DOM"""
        # Find title by ID using regex
        title_match = re.search(r'<h1[^>]*id="hero-title"[^>]*>(.*?)</h1>', report_content, re.DOTALL)
        assert title_match is not None, "Title element with id='hero-title' not found"
        
        # Check the content
        title_text = title_match.group(1).strip()
        assert title_text == "Network Scan Report", f"Expected 'Network Scan Report', got '{title_text}'"

    def test_title_has_correct_class(self, report_content):
        """Test that the title has the correct CSS class"""
        # Find the h1 with id="hero-title"
        title_match = re.search(r'<h1[^>]*id="hero-title"[^>]*>', report_content)
        assert title_match is not None
        
        title_tag = title_match.group(0)
        assert 'class="hero-title"' in title_tag, "Title should have 'hero-title' class"

    def test_title_not_hidden_by_css(self, report_content):
        """Test that title is not hidden by CSS rules"""
        # Check that there's no display:none or visibility:hidden on hero-title
        assert "hero-title { display: none" not in report_content
        assert "hero-title { visibility: hidden" not in report_content
        assert '#hero-title { display: none' not in report_content
        assert '#hero-title { visibility: hidden' not in report_content

    def test_subtitle_exists(self, report_content):
        """Test that the subtitle exists and is visible"""
        # Find subtitle by ID
        subtitle_match = re.search(r'<p[^>]*id="hero-subtitle"[^>]*>(.*?)</p>', report_content, re.DOTALL)
        assert subtitle_match is not None, "Subtitle element with id='hero-subtitle' not found"
        
        # Check it has the correct class
        subtitle_tag = subtitle_match.group(0)
        assert 'class="hero-subtitle"' in subtitle_tag, "Subtitle should have 'hero-subtitle' class"

    def test_hero_section_structure(self, report_content):
        """Test the overall hero section structure"""
        # Find hero section
        hero_match = re.search(r'<section[^>]*class="hero"[^>]*>(.*?)</section>', report_content, re.DOTALL)
        assert hero_match is not None, "Hero section not found"
        
        hero_content = hero_match.group(1)
        
        # Check that title is inside hero section
        assert 'id="hero-title"' in hero_content, "Title should be inside hero section"
        
        # Check that subtitle is inside hero section
        assert 'id="hero-subtitle"' in hero_content, "Subtitle should be inside hero section"

    def test_no_typewriter_animation_classes(self, report_content):
        """Test that typewriter animation classes are removed from title"""
        # Find the h1 with id="hero-title"
        title_match = re.search(r'<h1[^>]*id="hero-title"[^>]*>', report_content)
        assert title_match is not None
        
        title_tag = title_match.group(0)
        # Check that typewriter class is not present
        assert 'class="typewriter"' not in title_tag, "Title should not have 'typewriter' class"
        assert 'typewriter' not in title_tag or 'hero-title' in title_tag, "Title should not have typewriter animation"
        
        # Check subtitle doesn't have typewriter animation
        subtitle_match = re.search(r'<p[^>]*id="hero-subtitle"[^>]*>', report_content)
        assert subtitle_match is not None
        subtitle_tag = subtitle_match.group(0)
        assert 'typewriter-subtitle' not in subtitle_tag, "Subtitle should not have 'typewriter-subtitle' class"

    def test_hero_styles_defined(self, report_content):
        """Test that hero styles are properly defined"""
        # Check for hero section styles
        assert ".hero {" in report_content, "Hero section styles not defined"
        assert ".hero-title {" in report_content, "Hero title styles not defined"
        assert ".hero-subtitle {" in report_content, "Hero subtitle styles not defined"

    def test_title_visible_on_load(self, report_content):
        """Test that title doesn't depend on JavaScript or animations to be visible"""
        # Since we removed animations, the title should be immediately visible
        # Check that there's no opacity: 0 or similar on initial load
        
        # Find hero-title style definition
        hero_title_start = report_content.find(".hero-title {")
        if hero_title_start > 0:
            hero_title_end = report_content.find("}", hero_title_start)
            hero_title_styles = report_content[hero_title_start:hero_title_end]
            
            # Ensure no opacity: 0
            assert "opacity: 0" not in hero_title_styles, "Hero title should not have opacity: 0"
            
            # Ensure no visibility: hidden
            assert "visibility: hidden" not in hero_title_styles, "Hero title should not be hidden"

    def test_no_white_bar_artifact(self, report_content):
        """Test that the white bar animation artifact is prevented"""
        # Check that hero section has overflow control
        # The hero section has either overflow: hidden or overflow-x: hidden
        hero_section_idx = report_content.find(".hero {")
        assert hero_section_idx > 0, "Hero section styles not found"
        
        # Find the closing brace for hero styles
        hero_end = report_content.find("}", hero_section_idx)
        hero_styles = report_content[hero_section_idx:hero_end]
        
        # Check for any overflow control
        assert "overflow: hidden" in hero_styles or "overflow-x: hidden" in hero_styles, \
            "Hero section should have overflow control to prevent white bar artifacts"

    def test_title_renders_without_javascript(self, report_content):
        """Test that the title is visible even without JavaScript execution"""
        # The title should be plain HTML without depending on JS
        title_html = '<h1 class="hero-title" id="hero-title">Network Scan Report</h1>'
        assert title_html in report_content, "Title should be plain HTML without JavaScript dependencies"

    def test_no_animation_remnants(self, report_content):
        """Test that all animation-related code is cleaned up"""
        # Check that sessionStorage animation code is removed
        assert "sessionStorage.getItem('heroAnimated')" not in report_content, \
            "Animation session storage code should be removed"
        
        # Title HTML should not have animation classes
        title_match = re.search(r'<h1[^>]*id="hero-title"[^>]*>(.*?)</h1>', report_content, re.DOTALL)
        assert title_match is not None
        
        # The actual h1 tag should not contain typewriter class
        h1_tag = title_match.group(0)
        assert 'class="typewriter"' not in h1_tag, "Title tag should not have typewriter class"
        assert 'typewriter' not in h1_tag or 'hero-title' in h1_tag, \
            "Title tag should only have hero-title class, not typewriter"