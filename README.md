# cg-cert-check

```
usage: certificate-check.py [-h] [--slack-icon-emoji SLACK_ICON_EMOJI]
                            [--slack-username SLACK_USERNAME]
                            [--days-warn DAYS_WARN] [--days-error DAYS_ERROR]
                            [--no-bosh-check] [--no-elb-check]
                            [--slack-webhook SLACK_WEBHOOK]
                            [--slack-channel SLACK_CHANNEL]

Notify a slack channel when certificates in bosh manifests or used by ELBs are
about to expire.

optional arguments:
  -h, --help            show this help message and exit
  --slack-icon-emoji SLACK_ICON_EMOJI
                        An emoji to use as an icon. (default: :certificate:)
  --slack-username SLACK_USERNAME
                        The username to use when posting to slack. (default:
                        certificate-check)
  --days-warn DAYS_WARN
                        Raise a warning if a cert expires in this many days or
                        less. (default: 30)
  --days-error DAYS_ERROR
                        Raise an error if a cert expires in this many days or
                        less. (default: 7)
  --no-bosh-check       Do not check bosh deployments for certificates.
                        (default: False)
  --no-elb-check        Do not check elbs for certificates. (default: False)

Required arguments:
  --slack-webhook SLACK_WEBHOOK
                        A slack webhook URL used to for send alerts. (default:
                        None)
  --slack-channel SLACK_CHANNEL
                        A slack channel alerts should be sent to. (default:
                        None)

All arguments can be specified via environment variables. If both are
provided, arguments will override the environment.
```

## Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for additional information.

## Public domain

This project is in the worldwide [public domain](LICENSE.md). As stated in [CONTRIBUTING](CONTRIBUTING.md):

> This project is in the public domain within the United States, and copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication](https://creativecommons.org/publicdomain/zero/1.0/).
>
> All contributions to this project will be released under the CC0 dedication. By submitting a pull request, you are agreeing to comply with this waiver of copyright interest.
