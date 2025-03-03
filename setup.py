from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="baby-dpi",
    version="0.1.0",
    author="Anthony Wagonis",
    author_email="barefaced.code@gmail.com",
    description="A lightweight deep packet inspection and IPS utility",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/barefacedstorm/baby",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=[
        "scapy>=2.4.5",
        "dpkt>=1.9.7",
        "netaddr>=0.8.0",
    ],
    entry_points={
        'console_scripts': [
            'baby=baby.cli:main',
        ],
    },
)