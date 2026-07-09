from setuptools import setup, find_packages

setup(
    name="noctua",
    version="1.0.0",
    description="Tool-CyberSec-Forensic-Noctua - Reverse Engineering Framework en Python",
    author="MethodWhite",
    author_email="methodwhite@proton.me",
    url="https://github.com/MethodWhite/Noctua",
    packages=find_packages(),
    install_requires=[
        "capstone>=5.0",
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Assemblers",
        "Topic :: Software Development :: Disassemblers",
    ],
)
