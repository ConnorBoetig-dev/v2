"""
Unit tests for service filtering functionality in report templates
"""
import re
from pathlib import Path
import pytest


class TestServiceFiltering:
    """Test service filtering functionality in report templates"""

    @pytest.fixture
    def report_template_path(self):
        """Get path to main report template"""
        return Path(__file__).parent.parent.parent / "templates" / "report.html"

    @pytest.fixture
    def modular_template_path(self):
        """Get path to modular report template"""
        return Path(__file__).parent.parent.parent / "templates" / "report_modular.html"

    @pytest.fixture
    def report_content(self, report_template_path):
        """Load report template content"""
        with open(report_template_path, "r") as f:
            return f.read()

    def test_service_filter_function_exists(self, report_content):
        """Test that sortByService function is defined"""
        assert "function sortByService(serviceName)" in report_content
        assert "selectedServices = new Set()" in report_content

    def test_multi_select_support(self, report_content):
        """Test that multi-select filtering is implemented"""
        # Check for Set to track multiple selections
        assert "selectedServices = new Set()" in report_content
        assert "selectedServices.has(serviceName)" in report_content
        assert "selectedServices.add(serviceName)" in report_content
        assert "selectedServices.delete(serviceName)" in report_content

    def test_and_logic_implementation(self, report_content):
        """Test that AND logic is implemented for multiple services"""
        # Check for Array.every() which implements AND logic
        assert "Array.from(selectedServices).every(service =>" in report_content
        assert "hasAllServices" in report_content

    def test_clear_filters_function(self, report_content):
        """Test that clearServiceFilters function exists"""
        assert "function clearServiceFilters()" in report_content
        assert "selectedServices.clear()" in report_content

    def test_visual_feedback_elements(self, report_content):
        """Test visual feedback for selected services"""
        # Check for active class toggle
        assert "card.classList.add('active')" in report_content
        assert "card.classList.remove('active')" in report_content

        # Check for aria-pressed attribute
        assert "setAttribute('aria-pressed', 'true')" in report_content
        assert "setAttribute('aria-pressed', 'false')" in report_content

    def test_filter_indicator_ui(self, report_content):
        """Test filter indicator UI elements"""
        assert 'id="service-filter-indicator"' in report_content
        assert 'id="filtered-device-count"' in report_content
        assert "Filtering by" in report_content
        assert "Clear" in report_content

    def test_keyboard_accessibility(self, report_content):
        """Test keyboard accessibility features"""
        # Check for keyboard event handlers
        assert "addEventListener('keydown'" in report_content
        assert "e.key === 'Enter'" in report_content
        assert "e.key === ' '" in report_content

        # Check for ARIA attributes
        assert "setAttribute('tabindex', '0')" in report_content
        assert "setAttribute('role', 'button')" in report_content

    def test_css_visual_feedback(self, report_content):
        """Test CSS for visual feedback"""
        # Check for active state styles
        assert ".service-card.active {" in report_content
        assert ".service-card.active::before {" in report_content
        assert "content: '\\2713'" in report_content  # Checkmark

        # Check for focus styles
        assert ".service-card:focus {" in report_content
        assert "outline: 2px solid" in report_content

    def test_responsive_grid_css(self, report_content):
        """Test responsive CSS for service cards"""
        assert "@media (max-width: 768px)" in report_content
        assert "@media (max-width: 480px)" in report_content
        assert "grid-template-columns:" in report_content

    def test_device_row_filtering(self, report_content):
        """Test device row filtering logic"""
        # Check for display none/block logic
        assert "row.style.display = 'none'" in report_content
        assert "row.style.display = ''" in report_content

        # Check for regex-based service matching
        assert "RegExp" in report_content
        assert "\\\\b${service}\\\\b" in report_content

    def test_service_card_data_attributes(self, report_content):
        """Test service card has required data attributes"""
        # Check data attributes are present in template
        assert 'data-service="{{ service }}"' in report_content
        assert 'data-count="{{ count }}"' in report_content
        assert 'class="card glass hover-lift service-card"' in report_content

    def test_filter_state_management(self, report_content):
        """Test filter state is properly managed"""
        # Check for visible count tracking
        assert "visibleCount" in report_content
        assert "visibleCount++" in report_content

        # Check for device count display updates
        assert "Showing ${visibleCount} of ${totalDevices} devices" in report_content
        assert "Showing all ${totalDevices} devices" in report_content

    @pytest.mark.parametrize(
        "service_icon",
        [
            ("ssh", "🔐"),
            ("http", "🌐"),
            ("https", "🔒"),
            ("mysql", "🐬"),
            ("postgresql", "🐘"),
        ],
    )
    def test_service_icons_present(self, report_content, service_icon):
        """Test that common service icons are defined"""
        service, icon = service_icon
        assert f"service == '{service}'" in report_content
        assert icon in report_content

    def test_animation_keyframes(self, report_content):
        """Test animation keyframes for filter badge"""
        assert "@keyframes slideIn" in report_content
        assert "transform: translateY(-10px)" in report_content
        assert "transform: translateY(0)" in report_content
