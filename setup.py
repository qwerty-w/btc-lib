from setuptools import setup, find_packages  # type: ignore


def get_version() -> str:
    with open('btclib/__init__.py', 'r') as f:
        for line in f:
            if line.startswith('__version__'):
                return line.strip().split('= ')[-1].strip("'")

    raise RuntimeError('__version__ not found')


setup(
    name='btc-lib',
    version=get_version(),
    description='Simple Bitcoin Library',
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    author='qwerty-w',
    author_email='itsqwz@gmail.com',
    url='https://github.com/qwerty-w/btc-lib',
    packages=find_packages(exclude=['tests']),
    license='MIT',
    keywords=[
        'bitcoin',
        'blockchain',
        'library',
        'simple',
        'btc',
        'lib'
    ],
    install_requires=[
        'base58check~=1.0.2',
        'ecdsa~=0.19.0',
        'httpx~=0.27.0',
    ],
    python_requires='>=3.12'
)
