# Copyright (C) 2016-2017 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
from base64 import b64encode
from os.path import join
from logging import getLogger

import webob.exc

from soi.utils import empty_list_200
from soi.utils import check_activation
from soi.network_links import _snf_create_floating_ip
from soi.config import CREATE_SERVER_MAX_RETRIES

logger = getLogger(__name__)


@check_activation
def snf_index(cls, req):
    """Synnefo: list servers"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'servers_get'
    response = req.get_response(cls.app)
    return cls.get_from_response(response, "servers", [])


@check_activation
def snf_get_flavors(cls, req):
    """Synnefo: list flavors"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'flavors_get'
    req.environ['kwargs'] = {'detail': True}
    response = req.get_response(cls.app)
    r = cls.get_from_response(response, 'flavors', [])
    return [flavor for flavor in r if flavor['SNF:allow_create']]


@check_activation
def snf_get_images(cls, req):
    """Synnefo: list images"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'images_get'
    req.environ['kwargs'] = {'detail': True}
    response = req.get_response(cls.app)
    return cls.get_from_response(response, 'images', [])


def _openstackify_addresses(addresses, attachments):
    """Adjust server-nics to os-interface format
    This will affect addresses, not attachments, but attachments are used as
    input information
    """
    for att in attachments:
        net_id, mac_addr = att['network_id'], att['mac_address']
        for addr in addresses[net_id]:
            addr.setdefault('net_id', net_id)
            addr.setdefault('OS-EXT-IPS-MAC:mac_addr', mac_addr)


@check_activation
def snf_get_server(cls, req, server_id):
    """Synnefo: server info <server_id>"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'servers_get'
    req.environ['kwargs'] = {'server_id': server_id}
    response = req.get_response(cls.app)
    r = cls.get_from_response(response, "server", {})
    _openstackify_addresses(r['addresses'], r['attachments'])
    return r


@check_activation
def snf_get_flavor(cls, req, flavor_id):
    """Synnefo: flavor info <flavor_id>"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'flavors_get'
    req.environ['kwargs'] = {'flavor_id': flavor_id}
    response = req.get_response(cls.app)
    return cls.get_from_response(response, "flavor", {})


@check_activation
def snf_get_image(cls, req, image_id):
    """Synnefo: flavor info <image_id>"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'images_get'
    req.environ['kwargs'] = {'image_id': image_id}
    response = req.get_response(cls.app)
    return cls.get_from_response(response, "image", {})


@check_activation
def snf_get_server_volumes_link(cls, req, server_id):
    """Synnefo: server attachments <server_id>"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'volume_attachment_get'
    req.environ['kwargs'] = {'server_id': server_id}
    response = req.get_response(cls.app)
    return cls.get_from_response(response, "volumeAttachments", [])


def _openstackify_net_attachments(attachments):
    """OpenStack uses different keys for the same fields"""
    for a in attachments:
        a['net_id'] = a['network_id']
        a['mac_addr'] = a['mac_address']
        a['port_id'] = a['id']
        if a.get('OS-EXT-IPS:type', '') in ('fixed', ):
            fixed_ips, ipv4, ipv6 = {}, a.get('ipv4'), a.get('ipv6')
            if ipv4 or ipv6:
                fixed_ips['ip_address'] = ipv6 or ipv4
            a['fixed_ips'] = fixed_ips


@check_activation
def snf_get_server_net_attachments(cls, req, compute_id):
    """Adjust server-nics to os-interface format"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'servers_ips_get'
    req.environ['kwargs'] = {'server_id': compute_id}
    response = req.get_response(cls.app)
    r = cls.get_from_response(response, 'attachments', [])
    _openstackify_net_attachments(r)
    return r


def _get_personality(image, public_key):
    """Resolve superuser from VM, prepare public_key injection
    :returns: {contents: public_key, path: , owner: , group: , mode: }
    """
    pkey = b64encode(public_key)
    personality = [{
        'contents': pkey,
        'path': '/var/lib/cloud/seed/nocloud-net/meta-data'
    }]
    try:
        users = image['metadata']['users']
    except KeyError:
        return personality

    for user in users.split():
        prefix = '/' if user == 'root' else '/home'
        path = join(prefix, user, '.ssh', 'authorized_keys')
        personality.append(dict(
            contents=pkey, path=path, owner=user, group=user, mode=0600))
    return personality


@check_activation
def snf_create_server(cls, req, name, image, flavor, **kwargs):
    """Synnefo: create a new VM"""
    project = req.environ.get('HTTP_X_PROJECT_ID', None)
    body = dict(name=name, imageRef=image, flavorRef=flavor, project=project)

    personality, user_data = [], kwargs.pop('user_data', None)
    if user_data:
        personality.append({
            'contents': b64encode(user_data),
            'path': '/var/lib/cloud/seed/nocloud-net/user-data'})

    key_name = kwargs.pop('key_name', None)
    if key_name:
        public_key = req.environ.get('soi:public_keys', {}).get(key_name)
        if public_key:
            image_info = snf_get_image(cls, req, image)
            personality += _get_personality(image_info, public_key)

    if personality:
        body['personality'] = personality

    body.update(kwargs)

    if not body.get('networks', None):
        body.pop('networks', None)
    if not body.get('block_device_mapping_v2', None):
        body.pop('block_device_mapping_v2', None)

    for retry in range(CREATE_SERVER_MAX_RETRIES + 1):
        req.environ['kwargs'] = dict(json_data=dict(server=body))
        req.environ['service_type'] = 'compute'
        req.environ['method_name'] = 'servers_post'

        try:
            response = req.get_response(cls.app)
            break
        except webob.exc.HTTPConflict as ex:
            if (retry < CREATE_SERVER_MAX_RETRIES and
                    'Please create a floating IP' in '{}'.format(ex)):
                logger.warn('Could not find any available floating ip, ' +
                            'creating now (retry: {})'.format(retry+1))
                _snf_create_floating_ip(cls, req)
            else:
                raise

    r = cls.get_from_response(response, 'server', {})
    _openstackify_addresses(r['addresses'], r['attachments'])

    return r


@check_activation
def snf_delete_server(cls, req, server_id):
    """Synnefo: delete server"""
    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'servers_delete'
    req.environ['kwargs'] = {'server_id': server_id}
    req.get_response(cls.app)


@check_activation
def snf_run_action(cls, req, action, server_id):
    """Synnefo: server actions"""
    try:
        json_data = {
            'start': {'start': {}},
            'stop': {'shutdown': {}},
            'restart': {'reboot': {'type': 'SOFT'}}
        }[action]
    except KeyError:
        raise webob.exc.HTTPNotImplemented(
            explanation='Action {0} not supported'.format(action))

    req.environ['service_type'] = 'compute'
    req.environ['method_name'] = 'servers_action_post'
    req.environ['kwargs'] = {'server_id': server_id, 'json_data': json_data}
    req.get_response(cls.app)


@check_activation
def keypair_register(cls, req, name, public_key):
    """Put public key in req.environ['public_keys'], with name as key"""
    public_keys = req.environ.get('soi:public_keys', {})
    public_keys[name] = public_key
    req.environ['soi:public_keys'] = public_keys


function_map = {
    'index': snf_index,
    'get_server': snf_get_server,
    'get_flavors': snf_get_flavors,
    'get_flavor': snf_get_flavor,
    'get_images': snf_get_images,
    'get_image': snf_get_image,
    'get_server_volumes_link': snf_get_server_volumes_link,
    '_get_ports': snf_get_server_net_attachments,
    'delete': snf_delete_server,
    'create_server': snf_create_server,
    'run_action': snf_run_action,
    'keypair_create': keypair_register,
    'get_floating_ip_pools': empty_list_200,
}
