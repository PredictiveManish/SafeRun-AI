from setuptools import setup, find_packages

setup(
    name="saferun",
    version="0.1.0",
    description="Secure sandbox execution for AI-generated Python code",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "click>=8.0",
        "requests>=2.25",
    ],
    entry_points={
        "console_scripts": [
            "saferun=cli.main:cli",
        ],
    },
    python_requires=">=3.8",
)