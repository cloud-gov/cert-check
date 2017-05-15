from certcheck.sources.bosh import BoshDirector

import base64
import datetime

import boto3
import pem

from OpenSSL import crypto


def dict_generator(indict, pre=None):
    """Flatten a dict into a list of properties

    Based on http://stackoverflow.com/questions/12507206/
    """
    pre = pre[:] if pre else []

    if isinstance(indict, dict):
        for key, value in indict.items():
            if isinstance(value, dict):
                for d in dict_generator(value, pre + [key]):
                    yield d
            elif isinstance(value, list) or isinstance(value, tuple):
                for v in value:
                    for d in dict_generator(v, pre + [key]):
                        yield d
            else:
                yield pre + [key, value]
    else:
        yield pre + [indict]


def bosh_certificates(hostname, username, password, ca_cert=None):
    """Returns all certificates in all manifests on the given bosh director

    Args:
        hostname(str): the hostname or ip of the bosh director
        username(str): the username to authenticate with
        password(str): the password to authenticate with
        ca_cert(str, optional): The path to a pem encoded file

    Yields:
        list of tuples: (source(str), location(str), not_after(datetime.datetime))

    """
    b = BoshDirector(hostname, username, password, ca_cert=ca_cert)

    for deployment in b.deployments():
        for item in dict_generator(b.manifest(deployment['name'])):
            value = item.pop()
            key = ".".join(item)

            if isinstance(value, str):
                value = value.strip()
                certs = []
                # if it's pem encoded, iterate through the list
                if value.startswith('-----BEGIN CERTIFICATE-----'):
                    for entry in pem.parse(value.encode('utf-8')):
                        certs.append(crypto.load_certificate(crypto.FILETYPE_PEM, str(entry)))

                # if it's looks like ASN.1 then decode it that way
                if value.startswith('MII'):
                    try:
                        certs.append(crypto.load_certificate(crypto.FILETYPE_ASN1, base64.b64decode(value)))
                    except ValueError:
                        # looks like a cert, but we can't decode it?
                        # just ignore
                        pass

                for cert in certs:
                        not_after = datetime.datetime.strptime(
                            cert.get_notAfter().decode('utf-8'),
                            '%Y%m%d%H%M%SZ'
                        )

                        yield (deployment['name'], key, not_after)


def aws_elb_certificates():
    """Use boto3 to retrieve certificates in use by ELBS

    Yields:
        list of tuples: (source(str), location(str), not_after(datetime.datetime))
    """
    elbs = boto3.client('elb')
    iam = boto3.client('iam')

    certificates = {}

    # find all certs in-use by ELBs
    for elb in elbs.describe_load_balancers()['LoadBalancerDescriptions']:
        for listener in elb['ListenerDescriptions']:
            try:
                cert_arn = listener['Listener']['SSLCertificateId']
            except KeyError:
                # no TLS on this listener
                continue

            try:
                certificates[cert_arn].append(elb['LoadBalancerName'])
            except KeyError:
                certificates[cert_arn] = [elb['LoadBalancerName']]

    for cert_arn, elbs in certificates.items():
        # describe-load-balancers gives us the arn, but
        # get-server-certificate wants the name
        # the name _should_ be the last part of the arn
        cert_name = cert_arn.split('/').pop()

        cert_info = iam.get_server_certificate(
            ServerCertificateName=cert_name
        )['ServerCertificate']['ServerCertificateMetadata']

        # make sure our assumption above is correct
        assert cert_info['Arn'] == cert_arn

        yield ('AWS IAM ServerCertificate', cert_name, cert_info['Expiration'].replace(tzinfo=None))
