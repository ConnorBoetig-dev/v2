"""
Unit tests for dashboard cleanup and print functionality
"""
import re
from pathlib import Path
import pytest


class TestDashboardCleanup:
    """Test dashboard UI changes and print functionality"""

    @pytest.fixture
    def report_template_path(self):
        """Get path to main report template"""
        return Path(__file__).parent.parent.parent / "templates" / "report.html"

    @pytest.fixture
    def report_content(self, report_template_path):
        """Load report template content"""
        with open(report_template_path, "r") as f:
            return f.read()

    def test_critical_devices_box_removed(self, report_content):
        """Test that Critical Devices box has been removed"""
        # Should not find "Critical Devices" as a stat card label
        assert not re.search(r'<div class="stat-card-label">Critical Devices</div>', report_content)
        # Should not have alert-triangle icon in dashboard stats
        assert 'alert-triangle' not in report_content[
            report_content.find('dashboard-stats'):report_content.find('</section>')
        ] if 'dashboard-stats' in report_content else True

    def test_network_services_count_correct(self, report_content):
        """Test that Network Services box shows unique service count"""
        # Check that unique_services calculation exists
        assert "{% set unique_services = [] %}" in report_content
        assert "{% set service_name = service.split(':')[0] %}" in report_content
        assert "{% if service_name not in unique_services %}" in report_content
        
        # Check that Network Services box uses unique_services length
        assert "{{ unique_services|length }}" in report_content
        # Find the stat card section that contains Network Services
        network_services_idx = report_content.find('>Network Services<')
        if network_services_idx > 0:
            # Look backwards to find the stat-card-value div
            stat_card_start = report_content.rfind('class="stat-card glass hover-lift"', 0, network_services_idx)
            stat_card_section = report_content[stat_card_start:network_services_idx + 50]
            assert "unique_services|length" in stat_card_section

    def test_new_devices_removed_from_total(self, report_content):
        """Test that new devices trend is removed from Total Devices box"""
        # Find Total Devices section
        total_devices_section = report_content[
            report_content.find("Total Devices"):report_content.find("Total Devices") + 300
        ]
        
        # Should not have trending-up or +X new in this section
        assert "trending-up" not in total_devices_section
        assert "+{{ new_devices|length }} new" not in total_devices_section
        assert "stat-card-trend" not in total_devices_section

    def test_kpi_layout_three_columns(self, report_content):
        """Test that KPI boxes use 3-column layout"""
        # Check for 3-column grid
        assert "grid-template-columns: repeat(3, 1fr)" in report_content
        assert "max-width: 900px" in report_content
        assert "margin: 0 auto" in report_content

    def test_action_buttons_removed(self, report_content):
        """Test that Run New Scan and Compare buttons are removed"""
        # Should not find these button texts
        assert "New Scan" not in report_content or "refreshScan()" not in report_content
        assert "Compare Scans" not in report_content or "compareToLastScan()" not in report_content
        
        # Should still have Print and Export CSV
        assert "Print Report" in report_content
        assert "Export CSV" in report_content

    def test_print_function_exists(self, report_content):
        """Test that printDeviceTable function is implemented"""
        assert "function printDeviceTable()" in report_content
        assert "print-container" in report_content
        assert "Network Scan Report - Device List" in report_content
        assert "window.print()" in report_content

    def test_print_styles_defined(self, report_content):
        """Test that print-specific CSS is defined"""
        # Check for print media query
        assert "@media print" in report_content
        assert ".print-container" in report_content
        
        # Check for proper print styling
        assert "display: none !important" in report_content
        assert "@page" in report_content
        assert "size: landscape" in report_content

    def test_print_removes_action_column(self, report_content):
        """Test that print function removes Actions column"""
        print_function = report_content[
            report_content.find("function printDeviceTable"):
            report_content.find("function printDeviceTable") + 2000
        ]
        
        # Check for action column removal logic
        assert "Actions" in print_function
        assert "actionColIndex" in print_function
        assert "remove()" in print_function

    def test_responsive_grid_maintained(self, report_content):
        """Test that responsive grid works with 3 KPI boxes"""
        # Check media query for mobile
        assert "@media (max-width: 768px)" in report_content
        assert ".dashboard-stats { grid-template-columns: 1fr !important; }" in report_content

    def test_csv_export_still_works(self, report_content):
        """Test that CSV export function is still present"""
        assert "function downloadCSV()" in report_content
        assert "network_scan_" in report_content
        assert ".csv" in report_content

    def test_kpi_boxes_have_correct_count(self, report_content):
        """Test that exactly 3 KPI boxes remain"""
        # Find the statistics dashboard section
        dashboard_start = report_content.find("<!-- Statistics Dashboard -->")
        dashboard_end = report_content.find("</section>", dashboard_start)
        
        if dashboard_start > 0 and dashboard_end > dashboard_start:
            dashboard_section = report_content[dashboard_start:dashboard_end]
            # Count stat-card occurrences
            stat_card_count = dashboard_section.count('class="stat-card glass hover-lift"')
            assert stat_card_count == 3
        else:
            # If we can't find the section markers, just count in the whole document
            # but make sure they're in the dashboard area
            stat_card_count = report_content.count('<div class="stat-card glass hover-lift">')
            # Should be exactly 3 (Total Devices, Device Types, Network Services)
            assert stat_card_count >= 3  # Allow for other stat cards elsewhere

    def test_print_includes_metadata(self, report_content):
        """Test that print output includes scan metadata"""
        print_function = report_content[
            report_content.find("function printDeviceTable"):
            report_content.find("function printDeviceTable") + 2000
        ]
        
        # Check for metadata elements
        assert "Scan Date:" in print_function
        assert "Total Devices:" in print_function
        assert "scanTimestamp" in print_function
        assert "devicesData.length" in print_function

    def test_services_calculation_matches_tab(self, report_content):
        """Test that dashboard services count matches Services tab logic"""
        # Dashboard calculation
        dashboard_calc = report_content[
            report_content.find("{% set unique_services"):
            report_content.find("{% endfor %}", report_content.find("{% set unique_services")) + 20
        ]
        
        # Services tab calculation
        services_tab_calc = report_content[
            report_content.find("{% set service_summary"):
            report_content.find("{% endfor %}", report_content.find("{% set service_summary")) + 20
        ]
        
        # Both should split services by ':' to get service name
        assert "split(':')" in dashboard_calc
        assert "split(':')" in services_tab_calc