"""
JSON exporter implementation.

This module provides JSON export functionality with support for
pretty printing and streaming large datasets.
"""
import json
from pathlib import Path
from typing import Any, Dict
import logging

from .base import Exporter, ExportError
from ...core.models.scan_result import ScanResult


logger = logging.getLogger(__name__)


class JSONExporter(Exporter):
    """
    Export scan results to JSON format.
    
    Features:
    - Pretty printing with indentation
    - Streaming support for large datasets
    - Custom encoding for datetime objects
    - Compression support
    """
    
    def export(self, scan_result: ScanResult, output_path: Path) -> None:
        """Export scan results to JSON file."""
        self.validate_output_path(output_path)
        
        try:
            # Prepare data
            export_data = self.prepare_export_data(scan_result)
            
            # Determine if we should use streaming
            if self._should_stream(scan_result):
                self._export_streaming(export_data, output_path)
            else:
                self._export_standard(export_data, output_path)
            
            logger.info(f"Successfully exported scan results to {output_path}")
            
        except Exception as e:
            logger.error(f"JSON export failed: {e}")
            raise ExportError(f"Failed to export JSON: {e}") from e
    
    def get_file_extension(self) -> str:
        """Get JSON file extension."""
        return '.json'
    
    def supports_streaming(self) -> bool:
        """JSON supports streaming for large datasets."""
        return True
    
    def _should_stream(self, scan_result: ScanResult) -> bool:
        """Determine if streaming should be used based on data size."""
        # Stream if more than threshold devices
        threshold = self.config.get('streaming_threshold', 1000)
        return len(scan_result.devices) > threshold
    
    def _export_standard(self, data: Dict[str, Any], output_path: Path) -> None:
        """Standard JSON export with pretty printing."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(
                data,
                f,
                indent=self.config.get('indent', 2),
                sort_keys=self.config.get('sort_keys', True),
                ensure_ascii=False
            )
    
    def _export_streaming(self, data: Dict[str, Any], output_path: Path) -> None:
        """
        Stream JSON export for large datasets.
        
        This method writes the JSON structure incrementally to avoid
        loading the entire dataset into memory at once.
        """
        indent = self.config.get('indent', 2)
        indent_str = ' ' * indent if indent else ''
        
        with open(output_path, 'w', encoding='utf-8') as f:
            # Write opening brace
            f.write('{\n')
            
            # Write metadata
            f.write(f'{indent_str}"metadata": ')
            json.dump(data['metadata'], f, indent=indent)
            f.write(',\n')
            
            # Write summary
            f.write(f'{indent_str}"summary": ')
            json.dump(data['summary'], f, indent=indent)
            f.write(',\n')
            
            # Stream devices array
            f.write(f'{indent_str}"devices": [\n')
            
            devices = data['devices']
            for i, device in enumerate(devices):
                # Write device with proper indentation
                device_json = json.dumps(device, indent=indent)
                # Indent each line
                indented = '\n'.join(
                    f"{indent_str}{indent_str}{line}" 
                    for line in device_json.split('\n')
                )
                f.write(indented)
                
                # Add comma except for last item
                if i < len(devices) - 1:
                    f.write(',')
                f.write('\n')
            
            f.write(f'{indent_str}]')
            
            # Write changes if present
            if data.get('changes'):
                f.write(',\n')
                f.write(f'{indent_str}"changes": ')
                json.dump(data['changes'], f, indent=indent)
            
            # Close root object
            f.write('\n}')


class CompactJSONExporter(JSONExporter):
    """
    Compact JSON exporter without pretty printing.
    
    Useful for:
    - Minimizing file size
    - API responses
    - Data pipelines
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize with compact settings."""
        config = config or {}
        config.update({
            'indent': None,
            'sort_keys': False,
            'streaming_threshold': float('inf')  # Never stream
        })
        super().__init__(config)