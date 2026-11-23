import atexit
import os
import stat
import tempfile

import requests
import yaml


class BoshDirector(object):
    def __init__(self, hostname, username, password, port=25555, ca_cert=None):
        """Basic wrapper around the bosh director api. Basic auth and password grant is supported.

        Args:
            hostname(str): The hostname or ip of the bosh directory
            username(str): The username to authenticate as
            password(str): The password to authenticate with
            port(int): The port the bosh director is listening on
            ca_cert(str, optional): Either a path to an existing .PEM encoded
                CA bundle, or the raw PEM-encoded certificate content itself
                (e.g. as pulled from credhub). Raw content is written to a
                securely-created, process-local temp file since `requests`
                only accepts a file path for certificate verification.

        Raises:
            RuntimeError: The director requested an unknown authentication type
            ssl.SSLError: Error verifying the director's certificate
            requests.exceptions.HTTPError: Error communicating with the director or UAA
        """

        self.bosh_target = "https://{0}:{1}".format(hostname, port)
        self.ca_cert = self._prepare_ca_cert(ca_cert)
        self.token = None
        self.username = None
        self.password = None

        # figure out how to auth
        info = self._request('/info')

        # if it's UAA, do a password grant
        # TODO: implement client grant
        if info['user_authentication']['type'] == 'uaa':
            resp = requests.post(
                info['user_authentication']['options']['url'] + "/oauth/token",
                # https://github.com/cloudfoundry/bosh-cli/blob/master/cmd/session.go#L75
                auth=('bosh_cli', ''),
                data={
                    "grant_type": "password",
                    "username": username,
                    "password": password,
                },
                verify=self.ca_cert
            )
            resp.raise_for_status()

            self.token = resp.json()['access_token']

        # if it's basic, just stash the user/pass for later
        elif info['user_authentication']['type'] == 'basic':
            self.username = username
            self.password = password

        else:
            raise RuntimeError(
                "Unknown authentication type: {0}".format(info['user_authentication']['type'])
            )

    @staticmethod
    def _prepare_ca_cert(ca_cert):
        """Normalize `ca_cert` into a filesystem path usable by `requests`.

        `requests`' `verify` option only accepts a path to a CA bundle on
        disk, not raw PEM content. Historically this value was a path to a
        file fetched from S3 (e.g. via credhub-less pipelines). It can now
        also arrive as the raw PEM-encoded certificate contents directly
        from credhub (e.g. `((bosh-director-info.master.ca_cert))`). This
        detects which form was supplied and, for raw PEM content, writes it
        to a temp file (0600 perms, auto-registered for cleanup at process
        exit) so the rest of the code can keep treating `self.ca_cert` as a
        path uniformly.

        Args:
            ca_cert(str, optional): A filesystem path, raw PEM content, or None

        Returns:
            str/None: A filesystem path to a PEM-encoded CA bundle, or None
        """

        if not ca_cert:
            return ca_cert

        if '-----BEGIN CERTIFICATE-----' not in ca_cert:
            # looks like a path already (e.g. historical S3-sourced file)
            return ca_cert

        # raw PEM content (e.g. from credhub) - stash it in a temp file
        # since `requests` needs a path, not cert content, for `verify=`
        fd, path = tempfile.mkstemp(prefix='bosh-ca-cert-', suffix='.pem')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(ca_cert)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            os.unlink(path)
            raise

        atexit.register(lambda: os.path.exists(path) and os.unlink(path))

        return path

    def _request(self, endpoint, method='GET'):
        """Make a request to the bosh director

        Args:
            endpoint: The url to request
            method: The HTTP verb to use

        Raises:
            ssl.SSLError: Error verifying the director's certificate
            requests.exceptions.HTTPError: Error communicating with the director or UAA
        """

        # configure our settings
        kwargs = {}
        if self.ca_cert:
            kwargs['verify'] = self.ca_cert

        # decide which auth to use
        if self.token:
            kwargs['headers'] = {"Authorization": "bearer "+self.token}
        elif self.username and self.password:
            kwargs['auth'] = (self.username, self.password)

        # make the request
        resp = getattr(requests, method.lower())(self.bosh_target + endpoint, **kwargs)
        resp.raise_for_status()

        # return the result
        return resp.json()

    def deployments(self):
        """Return a list of deployments on the bosh director

        Returns:
            list: A list of dicts descriping the deployments on the director

        Raises:
            See _request()
        """
        return self._request('/deployments')

    def manifest(self, name):
        """Return a manifest for a specific deployment

        Args:
            name(str): The name of the deployment

        Returns:
            dict: The result of calling yaml.safe_load() on the returned manifest

        Raises:
            See _request()
        """
        manifest = self._request('/deployments/' + name)['manifest']
        return yaml.safe_load(manifest) if manifest is not None else {}
