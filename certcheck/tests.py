from certcheck.sources import BoshDirector, dict_generator, bosh_certificates, aws_elb_certificates

from datetime import datetime, timedelta
import unittest
import yaml

from mock import patch


class TestBoshDirector(unittest.TestCase):
    @patch('certcheck.sources.bosh.requests.get')
    def test_bosh_director_unknown_auth(self, mock_get):
        mock_get.return_value.json.return_value = {
            'user_authentication': {
                'type': "foo"
            }
        }

        with self.assertRaises(RuntimeError):
            BoshDirector('hostname', 'username', 'password')

    @patch('certcheck.sources.bosh.requests.get')
    @patch('certcheck.sources.bosh.requests.post')
    def test_bosh_director_uaa_auth(self, mock_post, mock_get):
        mock_get.return_value.json.side_effect = [
            {
                'user_authentication': {
                    'type': 'uaa',
                    'options': {
                        'url': 'http://hostname'
                    }
                }
            },
            [{'name': 'some-deployment'}, {'name': 'some-other-deployemt'}]
        ]

        mock_post.return_value.json.return_value = {'access_token': 'foo'}

        b = BoshDirector('hostname', 'username', 'password')

        self.assertEqual(b.token, 'foo')
        self.assertEqual(b.username, None)
        self.assertEqual(b.password, None)

        b.deployments()
        mock_get.assert_called_with(
            'https://hostname:25555/deployments',
            headers={'Authorization': 'bearer foo'}
        )

    @patch('certcheck.sources.bosh.requests.get')
    def test_bosh_director_basic_auth(self, mock_get):
        mock_get.return_value.json.side_effect = [
            {
                'user_authentication': {
                    'type': 'basic'
                }
            },
            {"manifest": "manifest-hurr"}
        ]

        b = BoshDirector('hostname', 'username', 'password', ca_cert='foo')

        self.assertEqual(b.token, None)
        self.assertEqual(b.username, 'username')
        self.assertEqual(b.password, 'password')
        self.assertEqual(b.ca_cert, 'foo')

        self.assertEqual(b.manifest('some-deployment'), 'manifest-hurr')
        mock_get.assert_called_with(
            'https://hostname:25555/deployments/some-deployment',
            auth=('username', 'password'),
            verify='foo'
        )

    @patch('certcheck.sources.bosh.requests.get')
    def test_bosh_director_manifest(self, mock_get):
        mock_get.return_value.json.side_effect = [
            {
                'user_authentication': {
                    'type': 'basic'
                }
            },
            {"manifest": None}
        ]

        b = BoshDirector('hostname', 'username', 'password', ca_cert='foo')
        self.assertEqual(b.manifest('some-deployment'), {})


class TestAWSCertificates(unittest.TestCase):

    @patch('certcheck.sources.boto3')
    def test_aws_elb_certificates(self, mock_boto):
        """Certificates can be extracted from AWS APIs"""
        mock_boto.client.return_value.describe_load_balancers.return_value = {
            'LoadBalancerDescriptions': [
                {
                    'LoadBalancerName': 'some-elb',

                    'ListenerDescriptions': [
                        {
                            'Listener': {
                                'SSLCertificateId': 'some-cert-arn'
                            }
                        }
                    ]
                },
                {
                    'LoadBalancerName': 'some-other-elb',

                    'ListenerDescriptions': [
                        {
                            # test listener with no SSL, it should be ignored
                            'Listener': {}
                        }
                    ]
                }
            ]
        }

        expires = datetime.utcnow()+timedelta(days=5)

        mock_boto.client.return_value.get_server_certificate.return_value = {
            'ServerCertificate': {
                'ServerCertificateMetadata': {
                    'Arn': 'some-cert-arn',
                    'Expiration': expires
                }
            }
        }

        output = list(aws_elb_certificates())

        self.assertEqual(output[0][1], "some-cert-arn")
        self.assertEqual(output[0][2], expires)

        print()


class TestBoshCertificates(unittest.TestCase):

    def test_dict_generator(self):
        """Complex datastructures can be flattened into a list"""
        output = list(dict_generator(yaml.load("""---
        this:
            is:
                a:
                    nested: item
        and:
            this-list-has:
            - nested:
                stuff:
                    that: works
            - normal: stuff
            - also-numbers: 916

        top-level-things: should-work

        """)))

        expected = [
            ['this', 'is', 'a', 'nested', 'item'],
            ['and', 'this-list-has', 'nested', 'stuff', 'that', 'works'],
            ['and', 'this-list-has', 'normal', 'stuff'],
            ['and', 'this-list-has', 'also-numbers', 916],
            ['top-level-things', 'should-work']
        ]

        for thing in expected:
            self.assertIn(thing, output)
            output.remove(thing)

        # nothing extra should be in our output
        self.assertEqual(len(output), 0)

    @patch("certcheck.sources.BoshDirector")
    def test_bosh_certificates(self, mock_bosh):
        """Single and multiple certificates can be extracted from a manifest"""
        mock_bosh.return_value.deployments.return_value = [{"name": "some-deployment"}]
        mock_bosh.return_value.manifest.return_value = yaml.load("""---
        this-is-a-single-certificate: |
            -----BEGIN CERTIFICATE-----
            MIIDQzCCAqygAwIBAgIJAMGs6m/j+u8sMA0GCSqGSIb3DQEBBQUAMHUxCzAJBgNV
            BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRMw
            EQYDVQQKEwpBbWF6b24uY29tMQwwCgYDVQQLEwNSRFMxHDAaBgNVBAMTE2F3cy5h
            bWF6b24uY29tL3Jkcy8wHhcNMTIwODE2MDY0MjAwWhcNMTcwODE1MDY0MjAwWjB1
            MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
            dHRsZTETMBEGA1UEChMKQW1hem9uLmNvbTEMMAoGA1UECxMDUkRTMRwwGgYDVQQD
            ExNhd3MuYW1hem9uLmNvbS9yZHMvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
            gQCnTB7AkRR4xuhfAuOt5foNeCRBPeUujkzmJu1yfnTbtFi+g7zmovQ9BJcRoPYL
            45McnXyaT/7UjhJhCI5gnYlTIyBTRFh7lXFJryypFx8AIh6q3D/ht8b6cVro3sJ2
            k4x1w/c7akKKsZJtf0ZyhbMvNnBz3K3TWVB6c9DChbfyUQIDAQABo4HaMIHXMB0G
            A1UdDgQWBBS/OwyfNJHDnAmnZBbq9ACiXz7O1jCBpwYDVR0jBIGfMIGcgBS/Owyf
            NJHDnAmnZBbq9ACiXz7O1qF5pHcwdTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
            c2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxEzARBgNVBAoTCkFtYXpvbi5jb20x
            DDAKBgNVBAsTA1JEUzEcMBoGA1UEAxMTYXdzLmFtYXpvbi5jb20vcmRzL4IJAMGs
            6m/j+u8sMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEACR37LqHlzjSH
            9gHCaiVJgCb0CCxSg3PHaQuv8h4ugAqQpGxpX3Zo97VgHnjEve21gXA74kzGUUAo
            7YNTZWbF2VkHUDqekXimvL3q1JEvHDKPkLJrxEic1zTU1uazb9uJeb1aVWTq6N8R
            bx56xd/e3o7RYcPfLD45y7RRXKz3AmE=
            -----END CERTIFICATE-----

        this-is-a-broken-pem-format: |
            -----BEGIN CERTIFICATE-----
            MIIDQzCCAqygAwIBAgIJAMGs6m/j+u8sMA0GCSqGSIb3DQEBBQUAMHUxCzAJBgNV
            BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMRMw
            EQYDVQQKEwpBbWF6b24uY29tMQwwCgYDVQQLEwNSRFMxHDAaBgNVBAMTE2F3cy5h
            bWF6b24uY29tL3Jkcy8wHhcNMTIwODE2MDY0MjAwWhcNMTcwODE1MDY0MjAwWjB1
            MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHU2Vh
            dHRsZTETMBEGA1UEChMKQW1hem9uLmNvbTEMMAoGA1UECxMDUkRTMRwwGgYDVQQD
            ExNhd3MuYW1hem9uLmNvbS9yZHMvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
            gQCnTB7AkRR4xuhfAuOt5foNeCRBPeUujkzmJu1yfnTbtFi+g7zmovQ9BJcRoPYL
            45McnXyaT/7UjhJhCI5gnYlTIyBTRFh7lXFJryypFx8AIh6q3D/ht8b6cVro3sJ2
            k4x1w/c7akKKsZJtf0ZyhbMvNnBz3K3TWVB6c9DChbfyUQIDAQABo4HaMIHXMB0G
            A1UdDgQWBBS/OwyfNJHDnAmnZBbq9ACiXz7O1jCBpwYD

        this-is-not-a-certificate: some-random-string

        this-is-not-an-asn1-cert: MII is what nintendo calls avatars

        this-is-a-cert-without-pem: |
            MIID9DCCAtygAwIBAgIBQjANBgkqhkiG9w0BAQUFADCBijELMAkGA1UEBhMCVVMx
            EzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIjAgBgNVBAoM
            GUFtYXpvbiBXZWIgU2VydmljZXMsIEluYy4xEzARBgNVBAsMCkFtYXpvbiBSRFMx
            GzAZBgNVBAMMEkFtYXpvbiBSRFMgUm9vdCBDQTAeFw0xNTAyMDUwOTExMzFaFw0y
            MDAzMDUwOTExMzFaMIGKMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3Rv
            bjEQMA4GA1UEBwwHU2VhdHRsZTEiMCAGA1UECgwZQW1hem9uIFdlYiBTZXJ2aWNl
            cywgSW5jLjETMBEGA1UECwwKQW1hem9uIFJEUzEbMBkGA1UEAwwSQW1hem9uIFJE
            UyBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuD8nrZ8V
            u+VA8yVlUipCZIKPTDcOILYpUe8Tct0YeQQr0uyl018StdBsa3CjBgvwpDRq1HgF
            Ji2N3+39+shCNspQeE6aYU+BHXhKhIIStt3r7gl/4NqYiDDMWKHxHq0nsGDFfArf
            AOcjZdJagOMqb3fF46flc8k2E7THTm9Sz4L7RY1WdABMuurpICLFE3oHcGdapOb9
            T53pQR+xpHW9atkcf3pf7gbO0rlKVSIoUenBlZipUlp1VZl/OD/E+TtRhDDNdI2J
            P/DSMM3aEsq6ZQkfbz/Ilml+Lx3tJYXUDmp+ZjzMPLk/+3beT8EhrwtcG3VPpvwp
            BIOqsqVVTvw/CwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUw
            AwEB/zAdBgNVHQ4EFgQUTgLurD72FchM7Sz1BcGPnIQISYMwHwYDVR0jBBgwFoAU
            TgLurD72FchM7Sz1BcGPnIQISYMwDQYJKoZIhvcNAQEFBQADggEBAHZcgIio8pAm
            MjHD5cl6wKjXxScXKtXygWH2BoDMYBJF9yfyKO2jEFxYKbHePpnXB1R04zJSWAw5
            2EUuDI1pSBh9BA82/5PkuNlNeSTB3dXDD2PEPdzVWbSKvUB8ZdooV+2vngL0Zm4r
            47QPyd18yPHrRIbtBtHR/6CwKevLZ394zgExqhnekYKIqqEX41xsUV0Gm6x4vpjf
            2u6O/+YE2U+qyyxHE5Wd5oqde0oo9UUpFETJPVb6Q2cEeQib8PBAyi0i6KnF+kIV
            A9dY7IHSubtCK/i8wxMVqfd5GtbA8mmpeJFwnDvm9rBEsHybl08qlax9syEwsUYr
            /40NawZfTUU=

        these-are-multiple-certs: |
            -----BEGIN CERTIFICATE-----
            MIID9DCCAtygAwIBAgIBQjANBgkqhkiG9w0BAQUFADCBijELMAkGA1UEBhMCVVMx
            EzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIjAgBgNVBAoM
            GUFtYXpvbiBXZWIgU2VydmljZXMsIEluYy4xEzARBgNVBAsMCkFtYXpvbiBSRFMx
            GzAZBgNVBAMMEkFtYXpvbiBSRFMgUm9vdCBDQTAeFw0xNTAyMDUwOTExMzFaFw0y
            MDAzMDUwOTExMzFaMIGKMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3Rv
            bjEQMA4GA1UEBwwHU2VhdHRsZTEiMCAGA1UECgwZQW1hem9uIFdlYiBTZXJ2aWNl
            cywgSW5jLjETMBEGA1UECwwKQW1hem9uIFJEUzEbMBkGA1UEAwwSQW1hem9uIFJE
            UyBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuD8nrZ8V
            u+VA8yVlUipCZIKPTDcOILYpUe8Tct0YeQQr0uyl018StdBsa3CjBgvwpDRq1HgF
            Ji2N3+39+shCNspQeE6aYU+BHXhKhIIStt3r7gl/4NqYiDDMWKHxHq0nsGDFfArf
            AOcjZdJagOMqb3fF46flc8k2E7THTm9Sz4L7RY1WdABMuurpICLFE3oHcGdapOb9
            T53pQR+xpHW9atkcf3pf7gbO0rlKVSIoUenBlZipUlp1VZl/OD/E+TtRhDDNdI2J
            P/DSMM3aEsq6ZQkfbz/Ilml+Lx3tJYXUDmp+ZjzMPLk/+3beT8EhrwtcG3VPpvwp
            BIOqsqVVTvw/CwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUw
            AwEB/zAdBgNVHQ4EFgQUTgLurD72FchM7Sz1BcGPnIQISYMwHwYDVR0jBBgwFoAU
            TgLurD72FchM7Sz1BcGPnIQISYMwDQYJKoZIhvcNAQEFBQADggEBAHZcgIio8pAm
            MjHD5cl6wKjXxScXKtXygWH2BoDMYBJF9yfyKO2jEFxYKbHePpnXB1R04zJSWAw5
            2EUuDI1pSBh9BA82/5PkuNlNeSTB3dXDD2PEPdzVWbSKvUB8ZdooV+2vngL0Zm4r
            47QPyd18yPHrRIbtBtHR/6CwKevLZ394zgExqhnekYKIqqEX41xsUV0Gm6x4vpjf
            2u6O/+YE2U+qyyxHE5Wd5oqde0oo9UUpFETJPVb6Q2cEeQib8PBAyi0i6KnF+kIV
            A9dY7IHSubtCK/i8wxMVqfd5GtbA8mmpeJFwnDvm9rBEsHybl08qlax9syEwsUYr
            /40NawZfTUU=
            -----END CERTIFICATE-----
            -----BEGIN CERTIFICATE-----
            MIIEATCCAumgAwIBAgIBRDANBgkqhkiG9w0BAQUFADCBijELMAkGA1UEBhMCVVMx
            EzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxIjAgBgNVBAoM
            GUFtYXpvbiBXZWIgU2VydmljZXMsIEluYy4xEzARBgNVBAsMCkFtYXpvbiBSRFMx
            GzAZBgNVBAMMEkFtYXpvbiBSRFMgUm9vdCBDQTAeFw0xNTAyMDUyMjAzMDZaFw0y
            MDAzMDUyMjAzMDZaMIGUMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3Rv
            bjEQMA4GA1UEBwwHU2VhdHRsZTEiMCAGA1UECgwZQW1hem9uIFdlYiBTZXJ2aWNl
            cywgSW5jLjETMBEGA1UECwwKQW1hem9uIFJEUzElMCMGA1UEAwwcQW1hem9uIFJE
            UyBhcC1ub3J0aGVhc3QtMSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
            ggEBAMmM2B4PfTXCZjbZMWiDPyxvk/eeNwIRJAhfzesiGUiLozX6CRy3rwC1ZOPV
            AcQf0LB+O8wY88C/cV+d4Q2nBDmnk+Vx7o2MyMh343r5rR3Na+4izd89tkQVt0WW
            vO21KRH5i8EuBjinboOwAwu6IJ+HyiQiM0VjgjrmEr/YzFPL8MgHD/YUHehqjACn
            C0+B7/gu7W4qJzBL2DOf7ub2qszGtwPE+qQzkCRDwE1A4AJmVE++/FLH2Zx78Egg
            fV1sUxPtYgjGH76VyyO6GNKM6rAUMD/q5mnPASQVIXgKbupr618bnH+SWHFjBqZq
            HvDGPMtiiWII41EmGUypyt5AbysCAwEAAaNmMGQwDgYDVR0PAQH/BAQDAgEGMBIG
            A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFIiKM0Q6n1K4EmLxs3ZXxINbwEwR
            MB8GA1UdIwQYMBaAFE4C7qw+9hXITO0s9QXBj5yECEmDMA0GCSqGSIb3DQEBBQUA
            A4IBAQBezGbE9Rw/k2e25iGjj5n8r+M3dlye8ORfCE/dijHtxqAKasXHgKX8I9Tw
            JkBiGWiuzqn7gO5MJ0nMMro1+gq29qjZnYX1pDHPgsRjUX8R+juRhgJ3JSHijRbf
            4qNJrnwga7pj94MhcLq9u0f6dxH6dXbyMv21T4TZMTmcFduf1KgaiVx1PEyJjC6r
            M+Ru+A0eM+jJ7uCjUoZKcpX8xkj4nmSnz9NMPog3wdOSB9cAW7XIc5mHa656wr7I
            WJxVcYNHTXIjCcng2zMKd1aCcl2KSFfy56sRfT7J5Wp69QSr+jq8KM55gw8uqAwi
            VPrXn2899T1rcTtFYFP16WXjGuc0
            -----END CERTIFICATE-----

        this-is-a-key-and-not-a-cert: |
            MIIEpAIBAAKCAQEAu24xlKdbnAVnbzqqr6H9VOvfQ0C9KoB0M8rrpyUkArA3wTgo
            EbvVU9rEkf7kTmW5jMEpuOIDT2+i8hlpUgWGTB53/XZ6E9o65KveqGrxmHaRL3FG
            8Vp0v/+64eanUqkwDD0RBS6UlIxBG4gyI7gfClRtqku06iiG+4+Wc8iklEjXJw1+
            VCsr8zIdsM/Lz9eYDgVNt6DcTBiUT5Qaq59XZrTaSmDkOFD5zdgJwHCme6SFd0QD
            vifEdjsOn/2qYe9AcXXsnzO7L+1rn2IeYpKXstCtcJoB7zG5BtvyYg1cAUBICvI3
            ns+yuFA/Tevsfy8AGe+0qvKXdfURcIBzvt4v4QIDAQABAoIBAEx1AQiw1G/qzGzV
            M7d9jwfLSEH48LGbwMs35bVDM1NdawEI1V+WjcktHq6nmZ5ZZL2ENm7S06Ld2UyF
            DS+GTWhTrYLZh6b9iLSrX6K4LWGSTFtcDCJ8Uc/Yk/V+z5aqqYz0hDLm83k9VXnT
            rxBfFVpzYmDrjRtP+PA5fJgyquBJuk7IqH21Q+evpoVaJ6mpE/6O4wtq02uHpJQ9
            gncrgplvs4/STynr5W/LDFUJ2JWKWW3Ep+b2aRSUdKCrsunmdaGMV8CKklNj+ZiC
            1odGUGzVy5RBKuHi28KQsRkHFH7ZlyfzLHOII7WekCQbLql737vr+5k28uwIgKmg
            tNZ8T6ECgYEA+DJ6fUYbQrJf5jOIi443I7f/KxJrzpVUic70YvB7HqyctG0eCDqk
            ZT0f/nO5bEYqotsDZKRF03cmVdhCon/cV8sSQ3tJHvy9nrDTEG7gsSgXLSRguuWu
            +rqYCXTyB5DaouKb5HzGVLYXP8m1p/o1vcaQcNYIXle4fNFKSbFbVu0CgYEAwVKo
            MVoTzXlmPOFqcSb60LBQxekBWvL35xKxT7Fa8KZ2BQr/HEzHiGgwfNRsLPshmyKj
            gSu1s2BHrDmfTZ45wLf9arKOBdc8n2dc+25kNIkYOKG/cWjehXsCljtqhsUuOGFx
            uhXeoMYLqyC+rWz9nS7aR9KrQE9KHTXOlnV0ikUCgYA8cz72KA8XrY5B6SdGpjqz
            zmqtuOzdAe33KprHRj8Wd4ArSbBY3L+RkNOsC8+LmYNk6ubmqkP/fzOtEOEZ5v5p
            u6IVIX/rti8Q6YxeokLDozoR2pxcqPh3RN8m3n7cbOFzbrH9co5zr232MVC3Ou+/
            6w7fDKI5KDBc5jSrwjC2+QKBgQCdOdA4cv3v+m+/y8R5yi3qU7sdembzxO8BKx6x
            pZhEZ91MNKlOJtOQiMwGeeyQmJ24Qe+gOiBIhmFEHIkG40wtBHZBtH31GhvfuHzS
            r/EnGOhuBn5gid2PyX9NF32Hpg31JKsNoIOzVd5fiv4Ipb+NenFkQF2uq82m+//M
            NjJV0QKBgQDtIjrAzT3Wgzcb0Pr6Oc+FSr/NzqGvEF+aoQD4Go9DiR7Rk2cHGU4g
            gVrf3JaBLHAl3Ep73s/qKkZSMfog8W4CfhGNMH6OPsWW0xWVLdrbrqAgyCK0TjQY
            7+dKmCQs+OVFRSiX86SDXRBPhi74fATarSHbzmfgVuJGRK22dGDvdw==
        """)

        output = list(bosh_certificates('bosh-hostname', 'bosh-username', 'bosh-password'))

        # we should find 4 total certs
        self.assertEqual(len([x[0] for x in output if x[0] == "some-deployment"]), 4)

        # we should find 1 single
        self.assertEqual(len([x[1] for x in output if x[1] == "this-is-a-single-certificate"]), 1)

        # and one without pem
        self.assertEqual(len([x[1] for x in output if x[1] == "this-is-a-cert-without-pem"]), 1)

        # we should find 2 multi
        self.assertEqual(len([x[1] for x in output if x[1] == "these-are-multiple-certs"]), 2)


if __name__ == '__main__':
    unittest.main()
