"""
Umbra Scanners - Setup Script
Instala o Umbra como comando global no sistema.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Lê o README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8') if (this_directory / "README.md").exists() else ""

# Lê requirements
requirements = []
requirements_file = this_directory / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='umbra-scanners',
    version='0.1.0',
    description='Ferramentas de reconhecimento e enumeração para testar o Umbra Core',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Seu Nome',
    author_email='seu@email.com',
    url='https://github.com/fromNexz/umbra-scanners',
    packages=find_packages(),
    include_package_data=True,
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'umbra=cli:main', 
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
    python_requires='>=3.10',
)