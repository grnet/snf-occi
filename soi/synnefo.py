# Copyright 2016 GRNET S.A. All rights reserved. #
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, self.list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, self.list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from soi.log import reveale_me
import json
from kamaki.clients.astakos import AstakosClient, CachedAstakosClient
from kamaki.clients.cyclades import CycladesComputeClient
from kamaki.clients.utils import https


#  Constants and classes for kamaki/synnefo calls
AUTH_URL = 'https://accounts.okeanos.grnet.gr/identity/v2.0'
ADMIN_TOKEN = 'some-token'
CA_CERTS = '/etc/ssl/certs/ca-certificates.crt'

https.patch_with_certs(CA_CERTS)
auth = CachedAstakosClient(AUTH_URL, ADMIN_TOKEN)

endpoints, client_classes = {}, {}
for cls in (AstakosClient, CycladesComputeClient):
    service_type = CycladesComputeClient.service_type
    endpoints[service_type] = auth.get_endpoint_url(service_type)
    client_classes[service_type] = cls


@reveale_me
def call_kamaki(environ, start_response, *args, **kwargs):
    """Initialize the requested kamaki client, call the requested method
    :param cls: the kamaki client Class, e.g, CycladesComputeClient
    :param method_name: name of the method to call, e.g. list_servers
    :param args: args for the method method
    :param kwargs: kwargs for the method
    :returns: the response from kamaki, WSGI compliant
    """
    service_type = environ.pop('service_type')
    method_name = environ.pop('method_name')
    kwargs = environ.pop('kwargs', {})

    endpoint = endpoints[service_type]
    token = environ['HTTP_X_AUTH_TOKEN']
    cls = client_classes[service_type]
    client = cls(endpoint, token)
    method = getattr(client, method_name)

    r = method(*args, **kwargs)

    body = _stringify_json_values(r.json)
    bodystr = json.dumps(body)

    headers, key = r.headers, 'content-length'
    if key in headers:
        headers[key] = '{0}'.format(len(bodystr))

    start_response('{0} {1}'.format(r.status_code, r.status), headers.items())
    return bodystr


def _stringify_json_values(data):
    """If a sinlge value is not a string, make it"""
    if isinstance(data, dict):
        return dict(
            map(lambda (k, v): (k, _stringify_json_values(v)), data.items()))
        # new_d = dict(data)
        # for k, v in data.items():
        #     new_d[k] = _stringify_json_values(v)
        # return new_d
    if isinstance(data, list):
        return map(_stringify_json_values, data)
    return '{0}'.format(data) if data else data
