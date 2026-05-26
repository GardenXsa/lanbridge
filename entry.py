"""Entry point for PyInstaller builds."""
import sys
import os

# Add the package directory to path for absolute imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lanbridge.cli import main

if __name__ == '__main__':
    main()
