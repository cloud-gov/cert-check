#!/usr/bin/env python3

import argparse
import datetime
import os

import requests

from certcheck.sources import bosh_certificates, aws_elb_certificates


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
        prog='certcheck',
        description='Notify a slack channel when certificates in bosh '
        'manifests or used by ELBs are about to expire.',
        epilog='All arguments can be specified via environment variables. '
        'If both are provided, arguments will override the environment.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--bosh-cli',
        help='The location of the bosh v2 cli',
        default=get_env('BOSH_CLI', 'bosh-cli')
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
    certificates = []

    # get certificages from bosh unless not allowed
    if args.no_bosh_check is False:
        certificates = certificates + list(bosh_certificates(
            get_env('BOSH_ENVIRONMENT'),
            get_env('BOSH_USERNAME'),
            get_env('BOSH_PASSWORD'),
            ca_cert=get_env('BOSH_CA_CERT')
        ))

    # get certificates from AWS unless not allowed
    if args.no_elb_check is False:
        certificates = certificates + list(aws_elb_certificates())

    # look for expired/expiring soon cert
    for source, location, not_after in certificates:
        expires = (not_after-datetime.datetime.utcnow()).days

        # if it's a problem, stash it
        if expires <= args.days_error:
            attachments.append(
                make_attachment(source, location, expires, 'danger')
            )
        elif expires <= args.days_warn:
            attachments.append(
                make_attachment(source, location, expires, 'warning')
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

        for attachment in attachments:
            print(attachment['text'])
