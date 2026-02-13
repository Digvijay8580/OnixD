#!/usr/bin/env python3
from setuptools import setup
import pathlib

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text() if (HERE / "README.md").exists() else "Web Vulnerability Scanner"

setup(
    name="OnixScanner",
    version="1.0.0",
    description="Simple Web Vulnerability Scanner for Students",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Digvijay8580/OnixD",
    py_modules=['onixscanner'],
    install_requires=[],
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            'onixscanner=onixscanner:main',
        ],
    },
)
