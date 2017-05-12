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
            ca_cert(str): A path to a .PEM encoded list of certificates to trust

        Raises:
            RuntimeError: The director requested an unknown authentication type
            ssl.SSLError: Error verifying the director's certificate
            requests.exceptions.HTTPError: Error communicating with the director or UAA
        """

        self.bosh_target = "https://{0}:{1}".format(hostname, port)
        self.ca_cert = ca_cert
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
            Seee _request()
        """
        return self._request('/deployments')

    def manifest(self, name):
        """Return a manifest for a specific deployment

        Args:
            name(str): The name of the deployment

        Returns:
            dict: The result of calling yaml.load() on the returned manifest

        Raises:
            Seee _request()
        """
        return yaml.load(self._request('/deployments/' + name)['manifest'])
