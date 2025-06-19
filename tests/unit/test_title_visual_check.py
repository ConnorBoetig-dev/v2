#!/usr/bin/env python3
"""
Simple visual check to confirm title renders correctly in the HTML template
"""
from pathlib import Path
import re


def visual_check():
    """Perform visual checks on the report template"""
    template_path = Path(__file__).parent.parent.parent / "templates" / "report.html"
    
    with open(template_path, "r") as f:
        content = f.read()
    
    print("=== Title Rendering Visual Check ===\n")
    
    # Find the hero section
    hero_match = re.search(r'<section[^>]*class="hero"[^>]*>(.*?)</section>', content, re.DOTALL)
    if hero_match:
        hero_content = hero_match.group(1)
        
        # Extract just the title and subtitle HTML
        title_match = re.search(r'<h1[^>]*>(.*?)</h1>', hero_content, re.DOTALL)
        subtitle_match = re.search(r'<p[^>]*class="hero-subtitle"[^>]*>(.*?)</p>', hero_content, re.DOTALL)
        
        if title_match:
            print("✅ TITLE FOUND:")
            print(f"   HTML: {title_match.group(0)}")
            print(f"   Text: {title_match.group(1).strip()}")
            print()
        else:
            print("❌ TITLE NOT FOUND")
            print()
            
        if subtitle_match:
            print("✅ SUBTITLE FOUND:")
            print(f"   HTML: {subtitle_match.group(0)[:100]}...")
            print()
        else:
            print("❌ SUBTITLE NOT FOUND")
            print()
    
    # Check for animation remnants
    print("=== Animation Check ===\n")
    
    if "sessionStorage.getItem('heroAnimated')" in content:
        print("❌ Animation code still present")
    else:
        print("✅ No animation code found")
        
    if '<span class="typewriter"' in content:
        print("❌ Typewriter span still present")
    else:
        print("✅ No typewriter span found")
        
    if 'class="typewriter-subtitle"' in content:
        print("❌ Typewriter subtitle class still present")
    else:
        print("✅ No typewriter subtitle class found")
    
    print("\n=== CSS Check ===\n")
    
    # Check hero styles
    hero_style_match = re.search(r'\.hero\s*\{([^}]+)\}', content)
    if hero_style_match:
        styles = hero_style_match.group(1)
        if "overflow: hidden" in styles or "overflow-x: hidden" in styles:
            print("✅ Hero section has overflow control")
        else:
            print("❌ Hero section missing overflow control")
    
    # Check title styles
    title_style_match = re.search(r'\.hero-title\s*\{([^}]+)\}', content)
    if title_style_match:
        styles = title_style_match.group(1)
        if "opacity: 0" not in styles and "visibility: hidden" not in styles:
            print("✅ Title is visible by default")
        else:
            print("❌ Title may be hidden by CSS")
    
    print("\n=== Summary ===\n")
    print("The title should render as:")
    print('  <h1 class="hero-title" id="hero-title">Network Scan Report</h1>')
    print("\nThis is a static title that appears immediately on page load.")
    print("No JavaScript or animations are required for it to be visible.")


if __name__ == "__main__":
    visual_check()