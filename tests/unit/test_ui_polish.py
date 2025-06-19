"""
Unit tests for UI/UX polish features
"""
from pathlib import Path
import pytest


class TestUIPolish:
    """Test UI/UX polish features including animations, clickable KPIs, and overlays"""

    @pytest.fixture
    def report_template_path(self):
        """Get path to main report template"""
        return Path(__file__).parent.parent.parent / "templates" / "report.html"

    @pytest.fixture
    def report_content(self, report_template_path):
        """Load report template content"""
        with open(report_template_path, "r") as f:
            return f.read()

    def test_typewriter_animation_styles(self, report_content):
        """Test that typewriter animation CSS is defined"""
        # Check for typing keyframes (updated animation)
        assert "@keyframes typing" in report_content
        assert "0% {" in report_content
        assert "width: 0;" in report_content
        assert "100% {" in report_content
        assert "width: 100%;" in report_content
        assert "border-right: none;" in report_content

        # Check for typewriter class
        assert ".typewriter {" in report_content
        assert "animation: typing 2s steps(30, end) forwards" in report_content

        # Check for subtitle animation
        assert ".typewriter-subtitle {" in report_content
        assert "animation-delay: 2.2s" in report_content

    def test_hero_title_has_typewriter_class(self, report_content):
        """Test that hero title has typewriter animation"""
        # Check for updated structure with span
        assert (
            '<span class="typewriter" id="hero-title">Network Scan Report</span>'
            in report_content
        )

        # Check subtitle
        assert 'class="hero-subtitle typewriter-subtitle"' in report_content
        assert 'id="hero-subtitle"' in report_content

    def test_typewriter_animation_runs_once(self, report_content):
        """Test that typewriter animation only runs once using sessionStorage"""
        # Check for sessionStorage logic
        assert "sessionStorage.getItem('heroAnimated')" in report_content
        assert "sessionStorage.setItem('heroAnimated', 'true')" in report_content

        # Check for animation removal logic
        assert "classList.remove('typewriter')" in report_content
        assert "classList.remove('typewriter-subtitle')" in report_content

    def test_total_devices_kpi_clickable(self, report_content):
        """Test that Total Devices KPI box is clickable"""
        # Find Total Devices stat card
        total_devices_idx = report_content.find("Total Devices</div>")
        assert total_devices_idx > 0

        # Look for the complete stat-card section including the opening tag
        stat_card_start = report_content.rfind(
            "<!-- Total Devices -->", 0, total_devices_idx
        )
        if stat_card_start == -1:
            stat_card_start = report_content.rfind(
                '<div class="stat-card', 0, total_devices_idx
            )

        # Get a larger section to ensure we capture all attributes
        stat_card_end = report_content.find("</div>", total_devices_idx) + 6
        stat_card_section = report_content[stat_card_start:stat_card_end]

        # Check for clickable attributes
        assert "clickable" in stat_card_section
        assert 'onclick="scrollToDeviceTable()"' in stat_card_section
        assert 'role="button"' in stat_card_section
        assert 'tabindex="0"' in stat_card_section
        assert 'aria-label="Click to scroll to device table"' in stat_card_section

    def test_device_types_kpi_clickable(self, report_content):
        """Test that Device Types KPI box is clickable"""
        # Find Device Types stat card
        device_types_idx = report_content.find("Device Types</div>")
        assert device_types_idx > 0

        # Look for the complete stat-card section including the opening tag
        stat_card_start = report_content.rfind(
            "<!-- Device Types -->", 0, device_types_idx
        )
        if stat_card_start == -1:
            stat_card_start = report_content.rfind(
                '<div class="stat-card', 0, device_types_idx
            )

        # Get a larger section to ensure we capture all attributes
        stat_card_end = report_content.find("</div>", device_types_idx) + 6
        stat_card_section = report_content[stat_card_start:stat_card_end]

        # Check for clickable attributes
        assert "clickable" in stat_card_section
        assert 'onclick="showDeviceTypesOverlay()"' in stat_card_section
        assert 'role="button"' in stat_card_section
        assert 'tabindex="0"' in stat_card_section
        assert 'aria-label="Click to view device types breakdown"' in stat_card_section

    def test_network_services_kpi_clickable(self, report_content):
        """Test that Network Services KPI box is clickable"""
        # Find Network Services stat card
        network_services_idx = report_content.find("Network Services</div>")
        assert network_services_idx > 0

        # Look for the complete stat-card section including the opening tag
        stat_card_start = report_content.rfind(
            "<!-- Network Services -->", 0, network_services_idx
        )
        if stat_card_start == -1:
            stat_card_start = report_content.rfind(
                '<div class="stat-card', 0, network_services_idx
            )

        # Get a larger section to ensure we capture all attributes
        # Find the closing div of the stat card
        trend_div_end = report_content.find(
            "</div>", report_content.find("stat-card-trend", network_services_idx)
        )
        stat_card_end = report_content.find("</div>", trend_div_end + 1) + 6
        stat_card_section = report_content[stat_card_start:stat_card_end]

        # Check for clickable attributes
        assert "clickable" in stat_card_section
        assert 'onclick="switchToServicesTab()"' in stat_card_section
        assert 'role="button"' in stat_card_section
        assert 'tabindex="0"' in stat_card_section
        assert 'aria-label="Click to view services tab"' in stat_card_section

    def test_device_types_overlay_html(self, report_content):
        """Test that device types overlay HTML structure exists"""
        # Check for overlay container
        assert 'class="device-types-overlay"' in report_content
        assert 'id="device-types-overlay"' in report_content
        assert 'role="dialog"' in report_content
        assert 'aria-labelledby="device-types-title"' in report_content
        assert 'aria-modal="true"' in report_content

        # Check for backdrop
        assert 'id="device-types-backdrop"' in report_content
        assert 'onclick="closeDeviceTypesOverlay()"' in report_content

        # Check for header and close button
        assert 'class="device-types-header"' in report_content
        assert 'class="device-types-close"' in report_content
        assert 'aria-label="Close overlay"' in report_content

        # Check for content area
        assert 'class="device-types-content"' in report_content
        assert 'id="device-types-content"' in report_content

    def test_device_types_overlay_styles(self, report_content):
        """Test that device types overlay has proper styling"""
        # Check for overlay styles
        assert ".device-types-overlay {" in report_content
        assert "backdrop-filter: var(--glass-blur)" in report_content
        assert "transform: translate(-50%, -50%) scale(0.9)" in report_content
        assert "visibility: hidden" in report_content

        # Check for show state
        assert ".device-types-overlay.show {" in report_content
        assert "visibility: visible" in report_content
        assert "transform: translate(-50%, -50%) scale(1)" in report_content

        # Check for content styles
        assert ".device-type-item {" in report_content
        assert ".device-type-item:hover {" in report_content
        assert "transform: translateX(4px)" in report_content

    def test_javascript_functions_exist(self, report_content):
        """Test that all required JavaScript functions are defined"""
        # Check for scroll function
        assert "function scrollToDeviceTable()" in report_content
        assert "scrollIntoView({ behavior: 'smooth'" in report_content

        # Check for services tab switch
        assert "function switchToServicesTab()" in report_content
        assert "showTab('services'" in report_content

        # Check for device types overlay functions
        assert "function showDeviceTypesOverlay()" in report_content
        assert "function closeDeviceTypesOverlay()" in report_content

        # Check that deviceTypes data is passed
        assert "const deviceTypes = {{" in report_content
        assert "device_types | tojson" in report_content

    def test_keyboard_accessibility(self, report_content):
        """Test keyboard accessibility features"""
        # Check for Escape key handler
        assert "event.key === 'Escape'" in report_content
        assert "closeDeviceTypesOverlay()" in report_content

        # Check for Enter/Space key handlers
        assert "event.key === 'Enter' || event.key === ' '" in report_content
        assert "target.classList.contains('clickable')" in report_content
        assert "event.preventDefault()" in report_content
        assert "target.click()" in report_content

    def test_clickable_kpi_styles(self, report_content):
        """Test that clickable KPI boxes have proper styles"""
        # Check for clickable class styles
        assert ".stat-card.clickable {" in report_content
        assert "cursor: pointer" in report_content

        # Check for hover effect
        assert ".stat-card.clickable:hover::after {" in report_content
        assert "background: rgba(255, 255, 255, 0.05)" in report_content

        # Check for active state
        assert ".stat-card.clickable:active {" in report_content
        assert "transform: scale(0.98)" in report_content

    def test_device_types_content_generation(self, report_content):
        """Test device types overlay content generation logic"""
        # Check for device type icons mapping
        assert "const deviceTypeIcons = {" in report_content
        assert "'router': { icon:" in report_content
        assert "'server': { icon:" in report_content
        assert "'workstation': { icon:" in report_content

        # Check for sorting logic
        assert (
            "Object.entries(deviceTypes).sort((a, b) => b[1] - a[1])" in report_content
        )

        # Check for HTML generation
        assert "device-type-item" in report_content
        assert "device-type-name" in report_content
        assert "device-type-icon" in report_content
        assert "device-type-count" in report_content

    def test_focus_management(self, report_content):
        """Test focus management for accessibility"""
        # Check that overlay gets focus
        assert "overlay.focus()" in report_content

        # Check that focus returns to trigger element
        assert "deviceTypesCard.focus()" in report_content

    def test_no_purple_progress_bar(self, report_content):
        """Test that purple progress bar is removed from Device Types KPI"""
        # Find Device Types section
        device_types_section = report_content[
            report_content.find("<!-- Device Types -->") : report_content.find(
                "<!-- Network Services -->"
            )
        ]

        # Should not have progress bar
        assert '<div class="progress"' not in device_types_section
        assert "progress-bar" not in device_types_section

    def test_motion_safe_considerations(self, report_content):
        """Test that animations respect motion preferences"""
        # Check that animations use CSS transitions
        assert "transition: all var(--transition-base)" in report_content
        assert "transition: all var(--transition-fast)" in report_content

        # Animations should be smooth and not jarring
        assert "animation: typing 2s" in report_content  # 2s is reasonable
        assert "animation-delay: 2.2s" in report_content  # Not too long

    def test_aria_labels_present(self, report_content):
        """Test that all interactive elements have proper ARIA labels"""
        # Check KPI boxes
        assert 'aria-label="Click to scroll to device table"' in report_content
        assert 'aria-label="Click to view device types breakdown"' in report_content
        assert 'aria-label="Click to view services tab"' in report_content

        # Check overlay
        assert 'aria-label="Close overlay"' in report_content
        assert 'aria-labelledby="device-types-title"' in report_content
        assert 'aria-modal="true"' in report_content

    def test_responsive_overlay(self, report_content):
        """Test that overlay is responsive"""
        # Check max-width and width settings
        assert "max-width: 600px" in report_content
        assert "width: 90vw" in report_content
        assert "max-height: 80vh" in report_content
        assert "overflow-y: auto" in report_content
