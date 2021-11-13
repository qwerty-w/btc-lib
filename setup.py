from setuptools import setup, find_packages

__version__ = '0.0.1'
__author__ = 'qwerty-w'

setup(
    name='btc-lib',
    version=__version__,
    description='Simple Bitcoin Library',
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    author=__author__,
    author_email='itsqwz@gmail.com',
    url='https://github.com/qwerty-w/btc-lib',
    packages=find_packages(exclude=['tests']),
    license='MIT',
    keywords=[
        'bitcoin',
        'library',
        'simple',
        'btc',
        'lib'
    ],
    install_requires=[
        'base58check~=1.0',
        'ecdsa~=0.17',
        'sympy~=1.8',
        'requests~=2.26',
    ],
    python_requires='~=3.10'
)
