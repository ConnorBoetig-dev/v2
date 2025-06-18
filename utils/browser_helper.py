#!/usr/bin/env python3
"""
Browser helper for opening URLs in both local and Docker environments
"""

import os
import subprocess
import webbrowser
import logging

logger = logging.getLogger(__name__)


def open_in_browser(url):
    """
    Open URL in browser, handling Docker environment appropriately.
    
    In Docker:
    - Uses host-open script to open URL on host system
    
    In local environment:
    - Uses standard webbrowser module
    
    Args:
        url: The URL to open
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Check if we're running in Docker
    is_docker = os.environ.get('DOCKER_HOST_BROWSER') == '1'
    
    if is_docker:
        # Running in Docker - use host-open script
        try:
            # Check if host-open script exists
            if os.path.exists('/usr/local/bin/host-open'):
                result = subprocess.run(
                    ['/usr/local/bin/host-open', url],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    logger.info(f"Opened {url} on host browser via Docker")
                    return True
                else:
                    logger.warning(f"Failed to open URL on host: {result.stderr}")
            else:
                logger.warning("host-open script not found in Docker container")
                
        except Exception as e:
            logger.error(f"Error opening URL in Docker: {e}")
            
        return False
    else:
        # Running locally - use standard webbrowser
        try:
            webbrowser.open(url)
            logger.info(f"Opened {url} in local browser")
            return True
        except Exception as e:
            logger.error(f"Error opening URL locally: {e}")
            return False


def can_open_browser():
    """
    Check if browser opening is available in current environment.
    
    Returns:
        bool: True if browser can be opened, False otherwise
    """
    is_docker = os.environ.get('DOCKER_HOST_BROWSER') == '1'
    
    if is_docker:
        # Check if host-open script is available
        return os.path.exists('/usr/local/bin/host-open')
    else:
        # In local environment, assume browser is available
        return True