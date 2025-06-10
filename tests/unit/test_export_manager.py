"""Unit tests for export manager module"""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest

from utils.export_manager import ExportManager


class TestExportManager:
    """Test export manager functionality"""

    @pytest.fixture
    def export_manager(self, tmp_path):
        """Create export manager instance"""
        return ExportManager(output_path=tmp_path)

    @pytest.fixture
    def sample_devices(self):
        """Sample devices for testing"""
        return [
            {
                "ip": "192.168.1.1",
                "hostname": "router.local",
                "mac": "00:11:22:33:44:55",
                "vendor": "Cisco",
                "type": "router",
                "os": "IOS",
                "services": ["ssh:22", "http:80"],
                "open_ports": [22, 80],
                "critical": True,
                "notes": "Main router",
                "vulnerability_count": 2,
                "critical_vulns": 0,
                "high_vulns": 1,
                "vulnerabilities": [
                    {"cve_id": "CVE-2023-001", "severity": "HIGH", "cvss_score": 7.5},
                    {"cve_id": "CVE-2023-002", "severity": "MEDIUM", "cvss_score": 5.0},
                ],
            },
            {
                "ip": "192.168.1.10",
                "hostname": "server.local",
                "mac": "00:AA:BB:CC:DD:EE",
                "vendor": "Dell",
                "type": "server",
                "os": "Ubuntu 20.04",
                "services": ["ssh:22", "http:80", "https:443"],
                "open_ports": [22, 80, 443],
                "critical": False,
                "notes": "",
                "vulnerability_count": 0,
                "critical_vulns": 0,
                "high_vulns": 0,
                "vulnerabilities": [],
            },
        ]

    @pytest.fixture
    def sample_changes(self):
        """Sample changes for testing"""
        return {
            "summary": {
                "total_current": 10,
                "total_previous": 8,
                "new_devices": 2,
                "missing_devices": 0,
                "changed_devices": 1,
            },
            "new_devices": [
                {"ip": "192.168.1.20", "hostname": "new-device", "type": "workstation"}
            ],
            "missing_devices": [],
            "changed_devices": [
                {
                    "ip": "192.168.1.1",
                    "changes": [{"field": "services", "action": "added", "value": "https:443"}],
                }
            ],
        }

    def test_init(self, export_manager):
        """Test export manager initialization"""
        assert export_manager.export_dir.exists()
        assert export_manager.export_dir.name == "exports"

    def test_export_to_json(self, export_manager, sample_devices, sample_changes):
        """Test JSON export"""
        result = export_manager.export_to_json(sample_devices, sample_changes)

        assert result.exists()
        assert result.suffix == ".json"

        # Verify content
        with open(result) as f:
            data = json.load(f)

        assert "metadata" in data
        assert "devices" in data
        assert "changes" in data
        assert len(data["devices"]) == 2
        assert data["metadata"]["total_devices"] == 2

    def test_export_to_csv_enhanced(self, export_manager, sample_devices):
        """Test enhanced CSV export"""
        result = export_manager.export_to_csv_enhanced(sample_devices)

        assert result.exists()
        assert result.suffix == ".csv"

        # Verify content
        with open(result) as f:
            content = f.read()

        assert "vulnerability_count" in content
        assert "192.168.1.1" in content
        assert "router.local" in content

    @patch("openpyxl.Workbook")
    def test_export_to_excel(self, mock_workbook, export_manager, sample_devices, sample_changes):
        """Test Excel export"""
        # Mock Excel workbook
        mock_wb = MagicMock()
        mock_ws = MagicMock()
        mock_wb.active = mock_ws
        mock_wb.create_sheet.return_value = MagicMock()
        mock_workbook.return_value = mock_wb

        result = export_manager.export_to_excel(sample_devices, sample_changes)

        assert str(result).endswith(".xlsx")
        assert mock_wb.save.called

        # Verify sheets were created
        assert mock_wb.create_sheet.call_count >= 3  # At least 4 sheets total

    @patch("reportlab.platypus.SimpleDocTemplate")
    @patch("reportlab.platypus.Paragraph")
    @patch("reportlab.platypus.Table")
    def test_export_to_pdf(
        self, mock_table, mock_para, mock_doc, export_manager, sample_devices, sample_changes
    ):
        """Test PDF export"""
        # Mock PDF components
        mock_doc_instance = MagicMock()
        mock_doc.return_value = mock_doc_instance

        result = export_manager.export_to_pdf(sample_devices, sample_changes)

        assert str(result).endswith(".pdf")
        assert mock_doc_instance.build.called

    def test_get_device_type_summary(self, export_manager, sample_devices):
        """Test device type summary generation"""
        summary = export_manager._get_device_type_summary(sample_devices)

        assert summary["router"] == 1
        assert summary["server"] == 1
        assert sum(summary.values()) == 2

    def test_get_service_summary(self, export_manager, sample_devices):
        """Test service summary generation"""
        summary = export_manager._get_service_summary(sample_devices)

        assert summary["ssh"] == 2  # Both devices have SSH
        assert summary["http"] == 2  # Both devices have HTTP
        assert summary["https"] == 1  # Only server has HTTPS

    def test_calculate_network_stats(self, export_manager, sample_devices):
        """Test network statistics calculation"""
        stats = export_manager._calculate_network_stats(sample_devices)

        assert stats["total_devices"] == 2
        assert stats["critical_devices"] == 1
        assert stats["vulnerable_devices"] == 1
        assert stats["total_open_ports"] == 5  # 2 + 3
        assert stats["unique_services"] == 3  # ssh, http, https
        assert stats["device_types"] == 2  # router, server

    def test_empty_devices(self, export_manager):
        """Test export with empty device list"""
        # JSON export
        result = export_manager.export_to_json([])
        assert result.exists()
        with open(result) as f:
            data = json.load(f)
        assert data["devices"] == []
        assert data["metadata"]["total_devices"] == 0

        # CSV export
        result = export_manager.export_to_csv_enhanced([])
        assert result.exists()

    def test_devices_with_no_vulnerabilities(self, export_manager):
        """Test export with devices having no vulnerabilities"""
        devices = [
            {
                "ip": "192.168.1.1",
                "hostname": "test",
                "type": "router",
                "services": [],
                "open_ports": [],
                "vulnerability_count": 0,
                "vulnerabilities": [],
            }
        ]

        result = export_manager.export_to_csv_enhanced(devices)
        assert result.exists()

        with open(result) as f:
            content = f.read()
        assert "No vulnerabilities detected" in content

    def test_pdf_export_error_handling(self, export_manager, sample_devices):
        """Test PDF export error handling"""
        with patch("reportlab.platypus.SimpleDocTemplate") as mock_doc:
            mock_doc.side_effect = Exception("PDF generation failed")

            # Should not raise exception
            result = export_manager.export_to_pdf(sample_devices)
            # Result path should still be returned even if generation failed
            assert str(result).endswith(".pdf")

    def test_excel_export_error_handling(self, export_manager, sample_devices):
        """Test Excel export error handling"""
        with patch("openpyxl.Workbook") as mock_wb:
            mock_wb.side_effect = Exception("Excel generation failed")

            # Should not raise exception
            result = export_manager.export_to_excel(sample_devices)
            # Result path should still be returned
            assert str(result).endswith(".xlsx")

    def test_vulnerability_summary_in_csv(self, export_manager, sample_devices):
        """Test vulnerability summary is correctly formatted in CSV"""
        result = export_manager.export_to_csv_enhanced(sample_devices)

        with open(result) as f:
            lines = f.readlines()

        # Find router line (has vulnerabilities)
        router_line = None
        for line in lines:
            if "192.168.1.1" in line:
                router_line = line
                break

        assert router_line is not None
        assert "1 high-risk issues" in router_line
        assert "CVE-2023-001" in router_line
