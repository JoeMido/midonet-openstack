# Copyright (C) 2012 Midokura KK
# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""MidoNet VIF driver for Libvirt."""

from webob import exc as w_exc

from oslo.config import cfg

from nova import utils
from nova.openstack.common import log as logging
from nova.virt.libvirt import config as vconfig
from nova.virt.libvirt import vif

from midonet.nova import midonet_connection

# Prepend 'nova' so Nova's logger handles.
LOG = logging.getLogger('nova...' + __name__)

midonet_vif_driver_opts = [
    cfg.StrOpt('midonet_host_uuid_path',
               default='/etc/midolman/host_uuid.properties',
               help='path to midonet host uuid file'),
    cfg.BoolOpt('midonet_use_tunctl',
                default=False,
                help='Use tunctl instead of ip command'),
    ]

CONF = cfg.CONF
CONF.register_opts(midonet_vif_driver_opts)
CONF.import_opt('libvirt_type', 'nova.virt.libvirt.driver')

MAX_MTU_SIZE = '65521' # 65535 minus 14-byte Ethernet header.

class MidonetVifDriver(vif.LibvirtBaseVIFDriver):

    def __init__(self, *args, **kwargs):
        self.mido_api = midonet_connection.get_mido_api()

    def get_config(self, instance, vif, image_meta, inst_type):

        vport_id = vif['id']
        dev_name = self.get_vif_devname(vif)

        # create vif (tap for kvm/qemu, veth for lxc) if not found
        create_device = True
        if self._device_exists(dev_name):
            create_device = False
        dev_name, peer_dev_name = self._create_vif(vif, create_device)

        # construct data for libvirt xml and return it.
        conf = vconfig.LibvirtConfigGuestInterface()
        if CONF.libvirt_use_virtio_for_bridges:
            conf.model = 'virtio'
        conf.net_type = 'ethernet'
        if CONF.libvirt_type == 'kvm' or CONF.libvirt_type == 'qemu':
            conf.target_dev = dev_name
        elif CONF.libvirt_type == 'lxc':
            conf.target_dev = peer_dev_name
        conf.script = ''
        conf.mac_addr = vif['address']
        return conf

    def _get_host_uuid(self):
        """
        Get MidoNet host id from host_uuid.properties file.
        """
        f = open(CONF.midonet_host_uuid_path)
        lines = f.readlines()
        host_uuid = filter(lambda x: x.startswith('host_uuid='),
                         lines)[0].strip()[len('host_uuid='):]
        return host_uuid

    def _device_exists(self, device):
        """Check if ethernet device exists."""
        (_out, err) = utils.execute('ip', 'link', 'show', 'dev', device,
                                    check_exit_code=False, run_as_root=True)
        return not err

    def _create_vif(self, vif, create_device):
        dev_name = self.get_vif_devname(vif)
        peer_dev_name = None
        if CONF.libvirt_type == 'lxc':
            peer_dev_name = 'lv' + dev_name[4:]

        if not create_device:
            return (dev_name, peer_dev_name)

        if CONF.libvirt_type == 'kvm' or CONF.libvirt_type == 'qemu':
            if CONF.midonet_use_tunctl:
                utils.execute('tunctl', '-p', '-t', dev_name,
                              run_as_root=True)
            else:
                utils.execute('ip', 'tuntap', 'add', dev_name, 'mode',
                              'tap', run_as_root=True)
        elif CONF.libvirt_type == 'lxc':
            utils.execute('ip', 'link', 'add', 'name', dev_name, 'type',
                          'veth', 'peer', 'name', peer_dev_name,
                          run_as_root=True)
            utils.execute('ip', 'link', 'set', 'dev', peer_dev_name, 'address',
                          vif['address'], run_as_root=True)
        utils.execute('ip', 'link', 'set', dev_name, 'up', 'mtu', MAX_MTU_SIZE,
                      run_as_root=True)
        return (dev_name, peer_dev_name)

    def _delete_tap(self, dev_name):
        utils.execute('ip', 'link', 'del', dev_name, run_as_root=True)

    def plug(self, instance, vif, **kwargs):
        """
        Creates if-vport mapping and returns interface data for the caller.
        """
        LOG.debug('instance=%r, vif=%r, kwargs=%r', instance, vif, kwargs)

        vport_id = vif['id']
        dev_name = self.get_vif_devname(vif)

        # create vif (tap for kvm/qemu, veth for lxc) if not found
        create_device = True
        if self._device_exists(dev_name):
            create_device = False
        dev_name, peer_dev_name = self._create_vif(vif, create_device)

        # create if-vport mapping.
        host_uuid = self._get_host_uuid()
        try:
            host = self.mido_api.get_host(host_uuid)
        except w_exc.HTTPError as e:
            LOG.error('Failed to create a if-vport mapping on host=%s',
                      host_uuid)
            raise e
        try:
            host.add_host_interface_port().port_id(vport_id)\
                .interface_name(dev_name).create()
        except w_exc.HTTPError as e:
            LOG.warn('Faild binding vport=%r to device=%r', vport_id, dev_name)

    def unplug(self, instance, vif, **kwargs):
        """
        Tear down the tap interface.
        Note that we don't need to tear down the if-vport mapping since,
        at this point, it should've been deleted when nova deleted the port.
        """
        LOG.debug('instance=%r, vif=%r, kwargs=%r', instance, vif, kwargs)
        try:
            vport_id = vif['id']
            dev_name = self.get_vif_devname(vif)

            # tear down the tap if it exists.
            if self._device_exists(dev_name):
                self._delete_tap(dev_name)
        except:
            # Swallowing exception to let the instance go.
            LOG.exception(_("Failed while unplugging vif=%s", dev_name),
                          instance=instance)
