"""
Unit tests for traffic flow visualization fixes
"""
import re
from pathlib import Path

import pytest


class TestTrafficFlowVisualization:
    """Test traffic flow visualization improvements"""

    @pytest.fixture
    def template_path(self):
        """Get path to traffic flow template"""
        return Path(__file__).parent.parent.parent / "templates" / "traffic_flow_report.html"

    def test_no_css_transform_on_hover(self, template_path):
        """Test that CSS transform scale is not used on node hover"""
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Check that .node:hover doesn't exist with transform scale
        # We're specifically looking for the problematic hover transform
        import re
        # Look for .node:hover with transform scale
        hover_pattern = re.compile(r'\.node:hover\s*\{[^}]*transform:\s*scale', re.DOTALL)
        assert not hover_pattern.search(content), ".node:hover should not have transform: scale"
        
        # Check that .node class exists
        assert ".node {" in content

    def test_hover_uses_stroke_instead(self, template_path):
        """Test that hover effect uses stroke changes instead of transform"""
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Find the mouseover handler
        mouseover_match = re.search(r'\.on\("mouseover",\s*function.*?\{(.*?)\}', content, re.DOTALL)
        assert mouseover_match is not None
        
        mouseover_content = mouseover_match.group(1)
        # Check that it modifies stroke
        assert "stroke-width" in mouseover_content
        assert "stroke" in mouseover_content
        assert "d3.select(this)" in mouseover_content
        
        # Find the mouseout handler
        mouseout_match = re.search(r'\.on\("mouseout",\s*function.*?\{(.*?)\}', content, re.DOTALL)
        assert mouseout_match is not None
        
        mouseout_content = mouseout_match.group(1)
        # Check that it resets stroke
        assert "stroke-width" in mouseout_content
        assert "stroke" in mouseout_content

    def test_drag_behavior_preserved(self, template_path):
        """Test that drag behavior is still implemented"""
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Check drag function exists
        assert "function drag(simulation)" in content
        assert "dragstarted" in content
        assert "dragged" in content
        assert "dragended" in content
        
        # Check drag is applied to nodes
        assert ".call(drag(simulation))" in content

    def test_force_simulation_exists(self, template_path):
        """Test that D3 force simulation is properly configured"""
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Check force simulation setup
        assert "d3.forceSimulation" in content
        assert "force(\"link\"" in content
        assert "force(\"charge\"" in content
        assert "force(\"center\"" in content
        assert "force(\"collision\"" in content

    def test_no_simulated_data_message(self, template_path):
        """Test that template shows warning for missing scapy or capture failure"""
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Check for updated warning messages
        assert "Traffic Capture Failed" in content
        assert "Scapy Not Installed" in content
        assert "pip install scapy" in content
        assert "./install_scapy.sh" in content

    def test_real_traffic_variable_check(self, template_path):
        """Test that template checks for real traffic capture"""
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Check that template uses real_traffic_captured variable
        assert "{% if not real_traffic_captured %}" in content
        assert "{% elif total_flows == 0 %}" in content

    def test_hover_visual_feedback(self, template_path):
        """Test that hover provides visual feedback"""
        with open(template_path, 'r') as f:
            content = f.read()
        
        # Check golden stroke on hover
        mouseover_match = re.search(r'\.on\("mouseover",.*?"#ffd93d"', content, re.DOTALL)
        assert mouseover_match is not None
        
        # Check stroke width increase
        assert re.search(r'\.attr\("stroke-width",\s*4\)', content) is not None
        
        # Check reset on mouseout
        assert re.search(r'\.attr\("stroke-width",\s*2\)', content) is not None
        assert re.search(r'\.attr\("stroke",\s*"#fff"\)', content) is not None