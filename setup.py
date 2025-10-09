#!/usr/bin/env python3
"""
Setup script for System Monitor Web Dashboard.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="system-monitor-dashboard",
    version="1.0.0",
    author="System Monitor Team",
    author_email="",
    description="A comprehensive web application for monitoring system services, active ports, and database status",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/system-monitor-dashboard",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "system-monitor=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "src": ["templates/*.html", "static/css/*", "static/js/*"],
    },
)
