"""
Unit tests for Subnets tab functionality
"""
from pathlib import Path
import pytest


class TestSubnetsTab:
    """Test Subnets tab including accordion, navigation, and keyboard support"""

    @pytest.fixture
    def report_template_path(self):
        """Get path to main report template"""
        return Path(__file__).parent.parent.parent / "templates" / "report.html"

    @pytest.fixture
    def report_content(self, report_template_path):
        """Load report template content"""
        with open(report_template_path, "r") as f:
            return f.read()

    def test_subnets_tab_exists(self, report_content):
        """Test that Subnets tab button exists in navigation"""
        # Check for tab button
        assert "onclick=\"showTab('subnets', this)\"" in report_content
        assert '<i data-feather="git-branch"' in report_content
        assert "Subnets" in report_content

        # Check for tab badge
        assert 'class="tab-badge"' in report_content
        assert "{{ subnet_summary|length }}" in report_content

    def test_subnets_tab_content_structure(self, report_content):
        """Test that Subnets tab content has correct structure"""
        # Check for tab content div
        assert 'id="subnets-tab"' in report_content
        assert 'class="tab-content"' in report_content

        # Check for section header
        assert "Network Subnets" in report_content
        assert "Discovered subnets and their devices" in report_content

        # Check for accordion container
        assert 'class="subnet-accordion"' in report_content
        assert 'id="subnet-accordion"' in report_content

    def test_subnet_card_structure(self, report_content):
        """Test subnet card HTML structure"""
        # Check for subnet card elements
        assert 'class="subnet-card"' in report_content
        assert 'data-subnet="{{ subnet.network }}"' in report_content
        assert 'onclick="toggleSubnet(' in report_content
        assert 'role="button"' in report_content
        assert 'tabindex="0"' in report_content
        assert 'aria-expanded="false"' in report_content
        assert 'aria-controls="subnet-content-' in report_content

        # Check for subnet header elements
        assert 'class="subnet-header"' in report_content
        assert 'class="subnet-info"' in report_content
        assert 'class="subnet-cidr"' in report_content
        assert 'class="subnet-badge"' in report_content
        assert "{{ subnet.device_count }} devices" in report_content

        # Check for toggle icon
        assert 'class="subnet-toggle"' in report_content
        assert 'aria-hidden="true"' in report_content
        assert "▼" in report_content

    def test_subnet_device_table(self, report_content):
        """Test that subnet cards contain device tables"""
        # Check for subnet content wrapper
        assert 'class="subnet-content"' in report_content
        assert 'class="subnet-devices"' in report_content

        # Find the subnet tab content
        subnet_tab_start = report_content.find('id="subnets-tab"')
        subnet_tab_end = report_content.find(
            "</div>\n\n        </div>\n    </main>", subnet_tab_start
        )
        subnet_tab_content = report_content[subnet_tab_start:subnet_tab_end]

        # Verify table headers in subnet tab
        assert "<th>IP Address</th>" in subnet_tab_content
        assert "<th>Hostname</th>" in subnet_tab_content
        assert "<th>MAC Address</th>" in subnet_tab_content
        assert "<th>Vendor</th>" in subnet_tab_content
        assert "<th>OS</th>" in subnet_tab_content
        assert "<th>Services</th>" in subnet_tab_content
        assert "<th>Actions</th>" in subnet_tab_content

    def test_subnet_filtering_logic(self, report_content):
        """Test that devices are filtered by subnet correctly"""
        # Check for subnet prefix calculation
        assert (
            "{% set subnet_prefix = subnet.network.split('/')[0].rsplit('.', 1)[0] %}"
            in report_content
        )

        # Check for device filtering
        assert "{% if device.ip.startswith(subnet_prefix + '.') %}" in report_content

    def test_accordion_css_styles(self, report_content):
        """Test that accordion CSS styles are defined"""
        # Check for accordion container styles
        assert ".subnet-accordion {" in report_content
        assert "flex-direction: column" in report_content

        # Check for card styles
        assert ".subnet-card {" in report_content
        assert "cursor: pointer" in report_content

        # Check for hover effects
        assert ".subnet-card:hover {" in report_content
        assert "box-shadow: var(--shadow-lg)" in report_content
        assert "transform: translateY(-2px)" in report_content

        # Check for expanded state
        assert ".subnet-card.expanded {" in report_content
        assert "border-color: var(--color-purple)" in report_content
        assert "box-shadow: 0 0 0 2px rgba(139, 92, 246, 0.2)" in report_content

        # Check for content animation
        assert ".subnet-content {" in report_content
        assert "max-height: 0" in report_content
        assert "overflow: hidden" in report_content
        assert "transition: max-height" in report_content

        assert ".subnet-card.expanded .subnet-content {" in report_content
        assert "max-height: 2000px" in report_content

    def test_toggle_icon_rotation(self, report_content):
        """Test that toggle icon rotates when expanded"""
        assert ".subnet-toggle {" in report_content
        assert "transition: transform var(--transition-fast)" in report_content

        assert ".subnet-card.expanded .subnet-toggle {" in report_content
        assert "transform: rotate(180deg)" in report_content

    def test_javascript_toggle_function(self, report_content):
        """Test that toggleSubnet function exists and works correctly"""
        # Check function definition
        assert "function toggleSubnet(subnet, event)" in report_content

        # Check accordion logic (only one expanded at a time)
        assert (
            "document.querySelectorAll('.subnet-card').forEach(c => {" in report_content
        )
        assert "c.classList.remove('expanded')" in report_content
        assert "c.setAttribute('aria-expanded', 'false')" in report_content

        # Check expansion logic
        assert "card.classList.add('expanded')" in report_content
        assert "card.setAttribute('aria-expanded', 'true')" in report_content

        # Check URL hash update
        assert (
            "history.replaceState(null, null, `#subnet=${encodeURIComponent(subnet)}`)"
            in report_content
        )

    def test_collapse_all_function(self, report_content):
        """Test collapseAllSubnets function"""
        assert "function collapseAllSubnets()" in report_content
        assert "currentExpandedSubnet = null" in report_content
        assert (
            "history.replaceState(null, null, window.location.pathname)"
            in report_content
        )

    def test_keyboard_navigation(self, report_content):
        """Test keyboard navigation support"""
        # Check for Escape key handling
        assert "if (event.key === 'Escape')" in report_content
        assert (
            "subnetsTab && subnetsTab.style.display !== 'none' && currentExpandedSubnet"
            in report_content
        )
        assert "collapseAllSubnets()" in report_content

        # Check for Enter/Space handling
        assert "if (target.classList.contains('subnet-card'))" in report_content
        assert "const subnet = target.getAttribute('data-subnet')" in report_content
        assert "toggleSubnet(subnet, event)" in report_content

    def test_url_hash_handling(self, report_content):
        """Test URL hash state management"""
        # Check hash change handler
        assert "function handleHashChange()" in report_content
        assert "if (hash.startsWith('#subnet='))" in report_content
        assert "const subnet = decodeURIComponent(hash.substring(8))" in report_content

        # Check that it switches to subnets tab
        assert "showTab('subnets', subnetsTab)" in report_content
        assert "setTimeout(() => toggleSubnet(subnet, null), 100)" in report_content

        # Check event listeners
        assert (
            "window.addEventListener('hashchange', handleHashChange)" in report_content
        )
        assert (
            "window.addEventListener('DOMContentLoaded', function()" in report_content
        )

    def test_tab_switching_preserves_state(self, report_content):
        """Test that tab switching preserves subnet state"""
        # Check that switching to subnets preserves hash
        assert "if (tabName === 'subnets' && currentExpandedSubnet)" in report_content
        assert (
            "history.replaceState(null, null, "
            "`#subnet=${encodeURIComponent(currentExpandedSubnet)}`)"
            in report_content
        )

        # Check that switching away clears hash
        assert "else if (tabName !== 'subnets')" in report_content
        assert (
            "history.replaceState(null, null, window.location.pathname)"
            in report_content
        )

    def test_typewriter_animation_fix(self, report_content):
        """Test that typewriter animation artifact is fixed"""
        # Check for improved animation
        assert "@keyframes typing" in report_content
        assert "100% {" in report_content
        assert "border-right: none;" in report_content

        # Check for wrapper span
        assert (
            '<span class="typewriter" id="hero-title">Network Scan Report</span>'
            in report_content
        )

        # Check for overflow fix
        assert ".hero {" in report_content
        assert "overflow-x: hidden;" in report_content

    def test_tab_badge_styles(self, report_content):
        """Test tab badge styling"""
        assert ".tab-badge {" in report_content
        assert "display: inline-flex" in report_content
        assert "background: var(--gradient-primary)" in report_content
        assert "color: white" in report_content
        assert "border-radius: var(--radius-sm)" in report_content
        assert "min-width: 20px" in report_content

    def test_subnet_card_accessibility(self, report_content):
        """Test accessibility features of subnet cards"""
        # Check ARIA attributes
        assert 'role="button"' in report_content
        assert 'tabindex="0"' in report_content
        assert 'aria-expanded="false"' in report_content
        assert 'aria-controls="subnet-content-' in report_content

        # Check that toggle icon is hidden from screen readers
        assert 'aria-hidden="true"' in report_content

    def test_no_purple_progress_bars(self, report_content):
        """Test that no purple progress bars exist in subnet cards"""
        subnet_section = report_content[
            report_content.find("<!-- Subnets Tab -->") : report_content.find(
                "</div>", report_content.find("<!-- Subnets Tab -->") + 2000
            )
        ]

        # Should not have progress bars
        assert '<div class="progress"' not in subnet_section
        assert "progress-bar" not in subnet_section

    def test_responsive_design(self, report_content):
        """Test that subnet accordion is responsive"""
        # Check that table is inside table-container
        assert 'class="table-container"' in report_content

        # Verify responsive grid is maintained
        assert "@media (max-width: 768px)" in report_content

    def test_feather_icon_reinit(self, report_content):
        """Test that feather icons are reinitialized after expansion"""
        # Check for feather.replace() calls in toggleSubnet function
        # Find the complete function
        func_start = report_content.find("function toggleSubnet")
        # Find the closing brace by counting braces
        brace_count = 0
        func_end = func_start
        found_first = False
        for i in range(func_start, min(func_start + 2000, len(report_content))):
            if report_content[i] == "{":
                brace_count += 1
                found_first = True
            elif report_content[i] == "}":
                brace_count -= 1
                if found_first and brace_count == 0:
                    func_end = i + 1
                    break

        toggle_function = report_content[func_start:func_end]
        assert "setTimeout(() => feather.replace(), 100)" in toggle_function
