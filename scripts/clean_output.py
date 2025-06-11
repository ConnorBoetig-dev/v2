#!/usr/bin/env python3
"""
Clean NetworkMapper Output Directories

This script removes all generated output files, reports, and scan data
to provide a clean slate for new scans.
"""

import os
import shutil
import sys
from pathlib import Path
from typing import List, Tuple

def get_output_directories() -> List[Path]:
    """Get all output directories relative to the project root."""
    # Get the project root (parent of scripts directory)
    project_root = Path(__file__).parent.parent
    
    # Define all output directories
    output_dirs = [
        project_root / "output",
        project_root / "output" / "scans",
        project_root / "output" / "reports", 
        project_root / "output" / "changes",
        project_root / "output" / "annotations",
        project_root / "exports",
    ]
    
    return output_dirs

def count_files(directory: Path) -> Tuple[int, int]:
    """Count files and subdirectories in a directory."""
    if not directory.exists():
        return 0, 0
    
    files = 0
    dirs = 0
    
    for item in directory.rglob("*"):
        if item.is_file():
            files += 1
        elif item.is_dir():
            dirs += 1
            
    return files, dirs

def clean_directory(directory: Path, preserve_structure: bool = True) -> Tuple[int, int]:
    """
    Clean a directory by removing all its contents.
    
    Args:
        directory: Path to the directory to clean
        preserve_structure: If True, keep the directory itself, only remove contents
        
    Returns:
        Tuple of (files_removed, dirs_removed)
    """
    if not directory.exists():
        return 0, 0
    
    files_removed = 0
    dirs_removed = 0
    
    # Count items before removal
    files_removed, dirs_removed = count_files(directory)
    
    if preserve_structure:
        # Remove only the contents, keep the directory
        for item in directory.iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
    else:
        # Remove the entire directory
        shutil.rmtree(directory)
        dirs_removed += 1  # Count the directory itself
        
    return files_removed, dirs_removed

def main():
    """Main cleanup function."""
    print("NetworkMapper Output Cleaner")
    print("=" * 50)
    
    output_dirs = get_output_directories()
    
    # First, show what will be cleaned
    print("\nDirectories to clean:")
    total_files = 0
    total_dirs = 0
    
    for directory in output_dirs:
        if directory.exists():
            files, dirs = count_files(directory)
            total_files += files
            total_dirs += dirs
            print(f"  • {directory.relative_to(directory.parent.parent)}: {files} files, {dirs} subdirectories")
        else:
            print(f"  • {directory.relative_to(directory.parent.parent)}: (does not exist)")
    
    if total_files == 0 and total_dirs == 0:
        print("\nNo files to clean. Output directories are already empty.")
        return
    
    # Ask for confirmation
    print(f"\nTotal: {total_files} files and {total_dirs} directories will be removed.")
    
    # Check for command line argument to skip confirmation
    if len(sys.argv) > 1 and sys.argv[1] in ["-y", "--yes"]:
        confirm = "y"
    else:
        confirm = input("\nAre you sure you want to clean all output? (y/N): ")
    
    if confirm.lower() != 'y':
        print("Cleanup cancelled.")
        return
    
    # Perform cleanup
    print("\nCleaning output directories...")
    total_files_removed = 0
    total_dirs_removed = 0
    
    for directory in output_dirs:
        if directory.exists():
            # For the main output and exports directories, preserve the structure
            # For subdirectories, also preserve them
            files, dirs = clean_directory(directory, preserve_structure=True)
            total_files_removed += files
            total_dirs_removed += dirs
            print(f"  ✓ Cleaned {directory.relative_to(directory.parent.parent)}")
    
    # Recreate the directory structure if needed
    print("\nRecreating directory structure...")
    for directory in output_dirs:
        directory.mkdir(parents=True, exist_ok=True)
        print(f"  ✓ Ensured {directory.relative_to(directory.parent.parent)} exists")
    
    # Add .gitkeep files to preserve empty directories in git
    for directory in output_dirs:
        gitkeep = directory / ".gitkeep"
        gitkeep.touch()
    
    print(f"\n✅ Cleanup complete!")
    print(f"   Removed {total_files_removed} files and {total_dirs_removed} directories.")
    print(f"   Output directories are ready for new scans.")

if __name__ == "__main__":
    main()