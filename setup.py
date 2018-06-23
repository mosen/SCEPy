from setuptools import setup, find_packages
setup(
    name="SCEPy",
    version="0.1",
    description="SCEPy is a pure python SCEP server implementation",
    packages=['scepy'],
    include_package_data=True,
    author="mosen",
    license="MIT",
    url="https://github.com/cmdmnt/SCEPy",
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6'
    ],
    keywords='SCEP',
    install_requires=[
        'asn1crypto>=0.22.0'
        'cryptography>=1.8.1',
        'Flask',
        'oscrypto>=0.18.0',
        'requests>=2.13.0'
    ],
    python_requires='>=3.5',
    tests_require=[
        'pytest',
        'mock'
    ],
    extras_requires={
        'ReST': [
            'Sphinx',
            'sphinxcontrib-napoleon'
        ]
    },
    setup_requires=['pytest-runner'],
    entry_points={
        'console_scripts': [
            'scepyclient=scepy.client:main',
        ]
    },
    zip_safe=False
)


