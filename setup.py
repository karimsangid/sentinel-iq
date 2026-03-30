from setuptools import setup, find_packages

setup(
    name="sentineliq",
    version="0.1.0",
    description="AI-powered security log analyzer",
    author="SentinelIQ Team",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.110.0",
        "uvicorn[standard]>=0.29.0",
        "pydantic>=2.6.0",
        "python-multipart>=0.0.9",
        "websockets>=12.0",
        "httpx>=0.27.0",
        "chromadb>=0.4.24",
        "ollama>=0.1.8",
        "aiosqlite>=0.20.0",
        "pandas>=2.2.0",
        "numpy>=1.26.0",
        "scikit-learn>=1.4.0",
        "python-dateutil>=2.9.0",
    ],
    entry_points={
        "console_scripts": [
            "sentineliq=main:main",
        ],
    },
)
