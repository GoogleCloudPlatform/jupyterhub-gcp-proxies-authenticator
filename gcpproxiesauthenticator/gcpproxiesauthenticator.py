# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from base64 import b64decode, b64encode
import json
import os
from urllib.parse import quote, urlparse
import uuid
from collections import namedtuple

from tornado import web
from tornado.auth import OAuth2Mixin
from tornado.log import app_log

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from traitlets import Unicode, Bool, List, default

import jwt
import requests


class ProxyUserLoginHandler(BaseHandler):
    """ Base class for ProxyUser login handler. """

    def dump(self, obj):
      for attr in dir(obj):
        if hasattr( obj, attr ):
          print( "obj.%s = %s" % (attr, getattr(obj, attr)))

    def get(self):
      """
      Uses the check_header parameters to retrieve the email of the already
      authenticated user.
      For JupyterHub + Inverting Proxy agent, use X-Inverting-Proxy-User-Id.
      For JupyterHub + Cloud IAP, X-Goog-IAP-JWT-Assertion. """

      if self.authenticator.check_header == "X-Inverting-Proxy-User-Id":

        b64_email = self.request.headers.get(self.authenticator.check_header, "")

        # Provides a dummy email to try the code locally.
        if b64_email == "" and self.authenticator.dummy_email:
          self.log.info(f'Using a dummy email {self.authenticator.dummy_email}')
          b64_email = b64encode(self.authenticator.dummy_email.encode('ascii'))

        if b64_email == "":
          raise web.HTTPError(401, f'Missing header {self.authenticator.check_header}')

        user_email = b64decode(b64_email).decode("ascii")
        self.log.info(f'user_email is {user_email}')

      elif self.authenticator.check_header == "X-Goog-IAP-JWT-Assertion":

        from googleapiclient import discovery
        from oauth2client.client import GoogleCredentials

        credentials = GoogleCredentials.get_application_default()
        compute = discovery.build('compute', 'v1', credentials=credentials,
                                  cache_discovery=False)

        request = compute.backendServices().get(
            project=self.authenticator.project_id,
            backendService=self.authenticator.backend_service_name
        )
        backend_service = request.execute()
        backend_service_id = backend_service['id']

        self.log.info(f'''self.authenticator.check_header name is
            {self.authenticator.check_header}''')
        self.log.info(f'''self.authenticator.check_header value is
            {self.request.headers.get(self.authenticator.check_header, "")}''')
        self.log.info(f'''self.authenticator.backend_service_id is
            {backend_service_id}''')

        _, user_email, _ = validate_iap_jwt_from_compute_engine(
            self.request.headers.get(self.authenticator.check_header, ""),
            self.authenticator.project_number,
            backend_service_id
        )

        if not user_email:
          raise web.HTTPError(401, 'Can not verify the IAP authentication.')

      else:
        raise web.HTTPError(400, 'Mismatch Authentication method and Header.')

      # username, _ = user_email.split("@")
      username = user_email.lower()
      user = self.user_from_username(username)

      # JupyterHub doesn't set the value for that key for some reason.
      if not hasattr(user, 'json_escaped_name'):
          setattr(user, 'json_escaped_name', json.dumps(user.name)[1:-1])

      self.log.info(f'username is {username}')
      self.log.info(f'user.name is {user.name}')

      self.set_login_cookie(user)

      self.write(
          self.render_template(
              self.authenticator.template_to_render,
              user=user,
              next_url=self.get_next_url(user),
          )
      )


class GCPProxiesAuthenticator(Authenticator):
    """ ProxyUser authenticator.

    Uses a header that refers to the already logged in user to do a silent
    authentication to JupyterHub.
    """
    login_handler = ProxyUserLoginHandler

    check_header = Unicode(
        '',
        config=True,
        help=""" Name of the header with the user's email """,
    )

    project_id = Unicode(
        '',
        config=True,
        help=""" Project id. """,
    )

    project_number = Unicode(
        '',
        config=True,
        help=""" Project number. """,
    )

    backend_service_name = Unicode(
        '',
        config=True,
        help=""" Name of the backend service where JupyterHub is deployed. Used
        with project_id, gets the backend service ID required to verify IAP.""",
    )

    dummy_email = Unicode(
        '',
        config=True,
        help=""" Dummy email in case no header and the ProxyUser must work. For
        example in a local environment. """,
    )

    template_to_render = Unicode(
        config=True,
        help=""" HTML page to render once the user is authenticated. For example
        'welcome.html'. """
    )

    def get_handlers(self, app):
        return [(r'/login', self.login_handler)]


# Cloud IAP related functions.
# Validata IAP header values and extract the user email.

def validate_iap_jwt_from_compute_engine(iap_jwt, cloud_project_number,
                                         backend_service_id):
    """ Validates an IAP JWT for your (Compute|Container) Engine service.

    Args:
      iap_jwt: The contents of the X-Goog-IAP-JWT-Assertion header.
      cloud_project_number: The project *number* for your Google Cloud project.
          This is returned by 'gcloud projects describe $PROJECT_ID', or
          in the Project Info card in Cloud Console.
      backend_service_id: The ID of the backend service used to access the
          application. See
          https://cloud.google.com/iap/docs/signed-headers-howto
          for details on how to get this value.

    Returns:
      (user_id, user_email, error_str).
    """
    expected_audience = '/projects/{}/global/backendServices/{}'.format(
        cloud_project_number, backend_service_id)
    return _validate_iap_jwt(iap_jwt, expected_audience)


def _validate_iap_jwt(iap_jwt, expected_audience):
    try:
        key_id = jwt.get_unverified_header(iap_jwt).get('kid')
        if not key_id:
            return (None, None, '**ERROR: no key ID**')
        key = get_iap_key(key_id)
        decoded_jwt = jwt.decode(
            iap_jwt, key,
            algorithms=['ES256'],
            issuer='https://cloud.google.com/iap',
            audience=expected_audience)
        return (decoded_jwt['sub'], decoded_jwt['email'], '')
    except (jwt.exceptions.InvalidTokenError,
            requests.exceptions.RequestException) as e:
        return (None, None, '**ERROR: JWT validation error {}**'.format(e))


def get_iap_key(key_id):
    """Retrieves a public key from the list published by Identity-Aware Proxy,
    re-fetching the key file if necessary.
    """
    key_cache = get_iap_key.key_cache
    key = key_cache.get(key_id)
    if not key:
        # Re-fetch the key file.
        resp = requests.get(
            'https://www.gstatic.com/iap/verify/public_key')
        if resp.status_code != 200:
            raise Exception(
                'Unable to fetch IAP keys: {} / {} / {}'.format(
                    resp.status_code, resp.headers, resp.text))
        key_cache = resp.json()
        get_iap_key.key_cache = key_cache
        key = key_cache.get(key_id)
        if not key:
            raise Exception('Key {!r} not found'.format(key_id))
    return key


# Used to cache the Identity-Aware Proxy public keys.  This code only
# refetches the file when a JWT is signed with a key not present in
# this cache.
get_iap_key.key_cache = {}
