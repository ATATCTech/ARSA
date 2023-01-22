from setuptools import setup

setup(
    name='arsa',
    version='1.1.9',
    description='A multilingual RSA library with segmented encryption and decryption and a unified format.',
    long_description='A multilingual RSA library with segmented encryption and decryption and unified format. All the '
                     'names of the methods and classes are the same in all languages.',
    author='ATATC',
    author_email='futerry@outlook.com',
    maintainer='ATATC',
    maintainer_email='futerry@outlook.com',
    license='MIT License',
    packages=['arsa'],
    platforms=['all'],
    include_package_data=True,
    url='https://github.com/ATATC/ARSA',
    classifiers=['Operating System :: OS Independent', 'Intended Audience :: Developers', 'License :: OSI Approved :: '
                                                                                          'MIT License', 'Programming '
                                                                                                         'Language :: '
                                                                                                         'Python',
                 'Programming Language :: Python :: Implementation', 'Programming Language :: Python :: 2',
                 'Programming Language :: Python :: 2.7', 'Programming Language :: Python :: 3', 'Programming '
                                                                                                 'Language :: Python '
                                                                                                 ':: 3.4',
                 'Programming Language :: Python :: 3.5', 'Programming Language :: Python :: 3.6', 'Programming '
                                                                                                   'Language :: '
                                                                                                   'Python :: 3.7',
                 'Topic :: Software Development :: Libraries'],
    install_requires=['Crypto>=1.4.1', 'pycryptodome>=3.9.7', 'setuptools>=66.1.1']
)
