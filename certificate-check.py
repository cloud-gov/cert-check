#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import subprocess
import yaml

import boto3
import requests

from OpenSSL import crypto


def bosh_cli(*args, _bosh_cli="bosh-cli"):
    """Run a command with the bosh v2 cli

    Args:
        *args(str): The arguments to bash to bosh;
        '--json' will be prepended to this list
        _bosh_cli: The path to the bosh v2 cli (optional)

    Returns:
        dict: The json output of the commaned parsed by json.loads()

    Raises:
        RuntimeError: There was a problem running the bosh command
        ValueError: There was a problem parsing the bosh output
    """

    returncode = 0
    command = [_bosh_cli, '--json'] + list(args)

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        output = exc.output
        returncode = exc.returncode

    try:
        response = json.loads(output.decode('utf-8'))
    except json.decoder.JSONDecodeError as exc:
        raise ValueError(
            "Could not parse output from `{0}`: {1}; "
            "Expected JSON, got: {2}".format(
                command,
                exc,
                output
            )
        )

    if returncode > 0:
        raise RuntimeError("Error when running {0}: {1}".format(
            command,
            "\n".join(response['Lines'])
        ))

    return response


def get_bosh_deployments():
    """Returns a list of deployments on the bosh director

    Yields:
        str: The names of a deployment

    Raises:
        See bosh_cli()
    """

    response = bosh_cli('deployments')

    for table in response['Tables']:
        for row in table['Rows']:
            yield row['name']


def get_bosh_manifest(deployment):
    """Returns the manifest for a given deployment

    Args:
        deployment(str): The name of the deployment

    Returns:
        dict: The manifest parsed by yaml.load()

    Raises:
        See bosh_cli()
    """

    response = bosh_cli('-d', deployment, 'manifest')

    return yaml.load(response['Blocks'][0])


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


def find_certificates(manifest):
    """Return any PEM encoded certificates in a manifest

    Args:
      manifest(dict): A bosh manifest loaded by yaml.load()

    Yields:
      tuple: (path.to.property, certificate)
    """

    for item in dict_generator(manifest):
        value = item.pop()
        key = ".".join(item)

        if isinstance(value, str):
            if value.strip().startswith('-----BEGIN CERTIFICATE-----'):
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, value)
                not_after = datetime.datetime.strptime(
                    cert.get_notAfter().decode('utf-8'),
                    '%Y%m%d%H%M%SZ'
                )

                yield (key, not_after)


def make_attachment(deployment, prop, expires, color):
    """Make a slack attachment for a cert warning/error

    Args:
        deployment(str): The name of the deployment containing `prop`
        prop(str): The property containing the certificate
        expires(int): The number of days until the cert expires
        (negative numbers if already expired)
        color: The color to use for the slack attachment

    Returns:
        dict: The formatted slack attachment
    """

    if expires < 0:
        status = "Expired!"
    elif expires == 0:
        status = "Expires today!"
    elif expires == 1:
        status = "Expires tomorrow!"
    elif expires > 1:
        status = "Expires in {0} days.".format(expires)

    attachment = {
        "color": color,
        "mrkdwn_in": ["text"],
        "text": "*{deployment}* `{property}`\n{status}".format(
            deployment=deployment,
            property=prop,
            status=status
        )
    }

    return attachment


def get_env(env_key, default=None):
    """A helper to access environment variables

    Args:
        env_key(str): The env var to retrieve
        default(bool, optional): The value to return if `env_key` does not exist

    Returns:
        str/mixed: The environment variable, or default
    """

    return os.environ.get(env_key, default)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Notify a slack channel when certificates in bosh '
        'manifests or used by ELBs are about to expire.',
        epilog='All arguments can be specified via environment variables. '
        'If both are provided, arguments will override the environment.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--slack-icon-emoji',
        help='An emoji to use as an icon.',
        default=get_env('SLACK_ICON_EMOJI', ':certificate:')
    )
    parser.add_argument(
        '--slack-username',
        help='The username to use when posting to slack.',
        default=get_env('SLACK_USERNAME', 'certificate-check')
    )
    parser.add_argument(
        '--days-warn',
        help='Raise a warning if a cert expires in this many days or less.',
        type=int,
        default=get_env('DAYS_WARN', 30)
    )
    parser.add_argument(
        '--days-error',
        help='Raise an error if a cert expires in this many days or less.',
        type=int,
        default=get_env('DAYS_ERROR', 7)
    )
    parser.add_argument(
        '--no-bosh-check',
        help='Do not check bosh deployments for certificates.',
        action='store_true',
        default=bool(get_env('NO_BOSH_CHECK', False))
    )
    parser.add_argument(
        '--no-elb-check',
        help='Do not check elbs for certificates.',
        action='store_true',
        default=bool(get_env('NO_ELB_CHECK', False))
    )

    required = parser.add_argument_group('Required arguments')
    required.add_argument(
        '--slack-webhook',
        help='A slack webhook URL used to for send alerts.',
        default=get_env('SLACK_WEBHOOK')
    )
    required.add_argument(
        '--slack-channel',
        help='A slack channel alerts should be sent to.',
        default=get_env('SLACK_CHANNEL')
    )

    args = parser.parse_args()

    # can't use requird=True above because
    # it'll error even if env var is set :(
    if args.slack_webhook is None or args.slack_channel is None:
        parser.error(
            'the following arguments are required: '
            '--slack-webhook, --slack-channel'
        )

    attachments = []

    if args.no_bosh_check is False:
        # find certs in all deployments on the director
        for name in get_bosh_deployments():
            for cert in find_certificates(get_bosh_manifest(name)):
                expires = (cert[1]-datetime.datetime.utcnow()).days

                # if it's a problem, stash it
                if expires <= args.days_error:
                    attachments.append(
                        make_attachment(name, cert[0], expires, 'danger')
                    )
                elif expires <= args.days_warn:
                    attachments.append(
                        make_attachment(name, cert[0], expires, 'warning')
                    )

    if args.no_elb_check is False:
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

            expires = (
                cert_info['Expiration'].replace(tzinfo=None) -
                datetime.datetime.utcnow()
            ).days

            if expires <= args.days_error:
                attachments.append(
                    make_attachment(
                        "AWS IAM ServerCertificate",
                        cert_name,
                        expires,
                        'danger'
                    )
                )
            elif expires <= args.days_warn:
                attachments.append(
                    make_attachment(
                        "AWS IAM ServerCertificate",
                        cert_name,
                        expires,
                        'warning'
                    )
                )

    # if we have something to say, say it
    if attachments:
        requests.post(
            args.slack_webhook,
            json={
                'username': args.slack_username,
                'channel': args.slack_channel,
                'icon_emoji': args.slack_icon_emoji,
                'attachments': attachments
            },
        ).raise_for_status()
