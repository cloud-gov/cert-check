from setuptools import setup, find_packages

with open('requirements.txt') as fh:
    required = fh.read().splitlines()

setup(
    name='certcheck',

    version='0.0.1',

    description='Notify a slack channel when certificates in bosh manifests'
    'or used by ELBs are about to expire.',

    url='https://github.com/18F/cg-cert-check',

    license='Public Domain',

    packages=find_packages(),

    install_requires=required,

    tests_require=[
        'mock'
    ],

    test_suite='certcheck.tests'
)