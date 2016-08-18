# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
topology_lib_ip communication library implementation.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

from ipaddress import ip_address, ip_network, ip_interface
from re import search
from re import match
from re import finditer
from re import DOTALL


def _parse_ip_addr(raw_result):
    """
    Parse the 'ip addr' command raw output

    :param str raw_result: cli raw string result
    :rtype: dict
    :return: The parsed result of the ip addr command in a dictionary \
        of the form:

    ::

    {
        '1': {
            'brd': '00:00:00:00:00:00',
            'dev': 'lo',
            'flags_str': ['LOOPBACK', 'UP', 'LOWER_UP'],
            'group': 'default',
            'inet': {
                '127.0.0.1': {
                    'mask': 8,
                    'preferred_lft': 'forever',
                    'scope': 'host lo',
                    'valid_lft': 'forever'
                }
            },
            'inet6': {
                '::1': {
                    'mask': 128,
                    'preferred_lft': 'forever',
                    'scope': 'host ',
                    'valid_lft': 'forever'
                }
            },
            'link': '00:00:00:00:00:00',
            'link_type': 'loopback',
            'mtu': 65536,
            'os_index': '1',
            'qdisc': 'noqueue',
            'qlen': 65536,
            'state': 'UNKNOWN'
        },
        '2': {
            'brd': 'ff:ff:ff:ff:ff:ff',
            'dev': 'bond0',
            'flags_str': ['BROADCAST', 'MULTICAST', 'MASTER'],
            'group': 'default',
            'inet': {},
            'inet6': {},
            'link': 'd6:f5:8c:08:ec:1a',
            'link_type': 'ether',
            'mtu': 1500,
            'os_index': '2',
            'qdisc': 'noop',
            'qlen': 1500,
            'state': 'DOWN'
        },
        '3': {
            'brd': 'ff:ff:ff:ff:ff:ff',
            'dev': 'eth0',
            'flags_str': ['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP'],
            'group': 'default',
            'inet': {
                '15.255.133.69': {
                    'brd': '15.255.135.255',
                    'mask': 21,
                    'preferred_lft': 'forever',
                    'scope': 'global eth0',
                    'valid_lft': 'forever'
                }
            },
            'inet6': {
                '2002:fff:853f:c:4a0f:cfff:feaf:605c': {
                    'mask': 64,
                    'preferred_lft': '0sec',
                    'scope': 'global deprecated dynamic ',
                    'valid_lft': '1888174sec'
                },
                'fe80::4a0f:cfff:feaf:605c': {
                    'mask': 64,
                    'preferred_lft': 'forever',
                    'scope': 'link ',
                    'valid_lft': 'forever'
                },
                'fec0::c:4a0f:cfff:feaf:605c': {
                    'mask': 64,
                    'preferred_lft': '0sec',
                    'scope': 'site deprecated dynamic ',
                    'valid_lft': '1888174sec'
                }
            },
           'link': '48:0f:cf:af:60:5c',
           'link_type': 'ether',
           'mtu': 1500,
           'os_index': '3',
           'qdisc': 'mq',
           'qlen': 1500,
           'state': 'UP'
        },
        '4': {
            'brd': 'ff:ff:ff:ff:ff:ff',
            'dev': 'bdev',
            'flags_str': ['BROADCAST', 'MULTICAST'],
            'group': 'default',
            'inet': {},
            'inet6': {},
            'link': '02:10:18:23:0b:41',
            'link_type': 'ether',
            'mtu': 1500,
            'os_index': '4',
            'qdisc': 'noop',
            'qlen': 1500,
            'state': 'DOWN'
        }
    }

    """

    result = {}
    ip_addr_re = {}
    ip_addr_re[0] = (
        r'(?P<os_index>\d+):\s(?P<dev>\S+):\s\<(?P<flags_str>\S+)\>\s'
        r'mtu\s(?P<mtu>\d+)\sqdisc\s(?P<qdisc>\S+)\sstate\s(?P<state>\S+)\s'
        r'group\s(?P<group>\S+)(\s+|\s+qlen\s+(?P<qlen>\d+))'
    )
    ip_addr_re[1] = (
        r'link\/(?P<link_type>\S+)\s(?P<link>\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2})\s'  # noqa
        r'brd\s(?P<brd>\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2})'
    )
    ip_addr_re[2] = (
        r'inet\s(?P<inet>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<inet_mask>\d+)\s'  # noqa
        r'scope\s(?P<scope>.*)'
    )
    ip_addr_re[3] = (
        r'inet\s(?P<inet>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(?P<inet_mask>\d+)\s'  # noqa
        r'brd\s(?P<brd>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s'
        r'scope\s(?P<scope>.*)'
    )
    ip_addr_re[4] = (
        r'inet6\s(?P<inet6>.*)/(?P<inet_mask>\d+)\s'
        r'scope\s(?P<scope>.*)'
    )
    ip_addr_re[5] = (
        r'valid_lft\s(?P<valid_lft>\S+)\s'
        r'preferred_lft\s(?P<preferred_lft>\S+)'
    )

    for x in raw_result.splitlines():
        if search(ip_addr_re[0], x):
            inet_flg = 0
            inet6_flg = 0
            m = search(ip_addr_re[0], x)
            interface_match = m.groupdict()
            interface_match['flags_str'] = interface_match['flags_str'].split(',')  # noqa
            interface_match['mtu'] = int(interface_match['mtu'])
            interface_match['qlen'] = int(interface_match['qlen'])
            result[interface_match['os_index']] = interface_match
            index = interface_match['os_index']
            result[index]["inet"] = {}
            result[index]["inet6"] = {}

        elif search(ip_addr_re[1], x):
            m = search(ip_addr_re[1], x)
            interface_match = m.groupdict()
            result[index].update(interface_match)

        elif search(ip_addr_re[2], x):
            m = search(ip_addr_re[2], x)
            interface_match = m.groupdict()
            inet_update = {
                interface_match['inet']: {
                    "mask": interface_match['inet_mask'],
                    "scope": interface_match['scope']
                }
            }
            result[index]["inet"].update(inet_update)
            inet_ip = interface_match['inet']
            inet_flg = 1

        elif search(ip_addr_re[3], x):
            m = search(ip_addr_re[3], x)
            interface_match = m.groupdict()
            inet_update = {
                interface_match['inet']: {
                    "mask": int(interface_match['inet_mask']),
                    "brd": interface_match['brd'],
                    "scope": interface_match['scope']
                }
            }
            result[index]["inet"].update(inet_update)
            inet_ip = interface_match['inet']
            inet_flg = 1

        elif search(ip_addr_re[4], x):
            m = search(ip_addr_re[4], x)
            interface_match = m.groupdict()
            inet6_update = {
                interface_match['inet6']: {
                    "mask": int(interface_match['inet_mask']),
                    "scope": interface_match['scope']
                }
            }
            result[index]["inet6"].update(inet6_update)
            inet6_ip = interface_match['inet6']
            inet6_flg = 1

        elif search(ip_addr_re[5], x):
            m = search(ip_addr_re[5], x)
            interface_match = m.groupdict()

            if inet_flg:
                inet_update = {
                    "valid_lft": interface_match['valid_lft'],
                    "preferred_lft": interface_match['preferred_lft']
                }
                result[index]["inet"][inet_ip].update(inet_update)
                inet_flg = 0
                inet_ip = {}

            elif inet6_flg:
                inet6_update = {
                    "valid_lft": interface_match['valid_lft'],
                    "preferred_lft": interface_match['preferred_lft']
                }
                result[index]["inet6"][inet6_ip].update(inet6_update)
                inet6_flg = 0
                inet6_ip = {}

    return result


def _parse_ip_addr_show(raw_result):
    """
    Parse the 'ip addr list dev' command raw output.

    :param str raw_result: os raw result string.
    :rtype: dict
    :return: The parsed result of the show interface command in a \
        dictionary of the form:

     ::

        {
            'os_index' : '0',
            'dev' : 'eth0',
            'falgs_str': 'BROADCAST,MULTICAST,UP,LOWER_UP',
            'mtu': 1500,
            'state': 'down',
            'link_type' 'ether',
            'mac_address': '00:50:56:01:2e:f6',
            'inet': '20.1.1.2',
            'inet_mask': '24',
            'inet6': 'fe80::42:acff:fe11:2',
            'inte6_mask': '64'
        }
    """
    # does link exist?
    show_re = (
        r'"(?P<dev>\S+)"\s+does not exist'
    )
    re_result = search(show_re, raw_result)
    result = None

    if not (re_result):
        # match top two lines for serveral 'always there' variables
        show_re = (
            r'\s*(?P<os_index>\d+):\s+(?P<dev>\w+):\s+<(?P<falgs_str>.*)?>.*?'
            r'mtu\s+(?P<mtu>\d+).+?state\s+(?P<state>\w+).*'
            r'\s*link/(?P<link_type>\w+)\s+(?P<mac_address>\S+)'
        )

        re_result = search(show_re, raw_result, DOTALL)
        result = re_result.groupdict()

        # seek inet if its there
        show_re = (
                r'((inet )\s*(?P<inet>[^/]+)/(?P<inet_mask>\d{1,2}))'
            )
        re_result = search(show_re, raw_result)
        if (re_result):
            result.update(re_result.groupdict())

        # seek inet6 if its there
        show_re = (
                r'((?<=inet6 )(?P<inet6>[^/]+)/(?P<inet6_mask>\d{1,2}))'
            )
        re_result = search(show_re, raw_result)
        if (re_result):
            result.update(re_result.groupdict())

        # cleanup dictionary before returning
        for key, value in result.items():
            if value is not None:
                if value.isdigit():
                    result[key] = int(value)

    return result


def _parse_ip_link(raw_result):
    """
    Parse the 'ip link' command raw output

    :param str raw_result: cli raw string result
    :rtype: dict
    :return: The parsed result of the ip link command in a dictionary \
        of the form:

    ::

        {
            '1': {
                'qlen': 65536,
                'qdisc': 'noqueue',
                'group': 'default',
                'flags_str': [
                    'LOOPBACK',
                    'UP',
                    'LOWER_UP'
                ],
                'os_index': '1',
                'dev': 'lo',
                'mtu': 65536,
                'state': 'UNKNOWN',
                'link': '00:00:00:00:00:00',
                'mode': 'DEFAULT',
                'brd': '00:00:00:00:00:00',
                'link_type': 'loopback'
            },
            '2': {
                'qlen': 1500,
                'qdisc': 'noop',
                'group': 'default',
                'flags_str': [
                    'BROADCAST',
                    'MULTICAST',
                    'MASTER'
                ],
                'os_index': '2',
                'dev': 'bond0',
                'mtu': 1500,
                'state': 'DOWN',
                'link': 'd6:f5:8c:08:ec:1a',
                'mode': 'DEFAULT',
                'brd': 'ff:ff:ff:ff:ff:ff',
                'link_type': 'ether'
            },
            '3': {
                'qlen': 1500,
                'qdisc': 'mq',
                'group': 'default',
                'flags_str': [
                    'BROADCAST',
                    'MULTICAST',
                    'UP',
                    'LOWER_UP'
                ],
                'os_index': '3',
                'dev': 'eth0',
                'mtu': 1500,
                'state': 'UP',
                'link': '48:0f:cf:af:60:5c',
                'mode': 'DEFAULT',
                'brd': 'ff:ff:ff:ff:ff:ff',
                'link_type': 'ether'
            },
            '4': {
                'qlen': 1500,
                'qdisc': 'noop',
                'group': 'default',
                'flags_str': [
                    'BROADCAST',
                    'MULTICAST'
                ],
                'os_index': '4',
                'dev': 'bdev',
                'mtu': 1500,
                'state': 'DOWN',
                'link': '02:10:18:23:0b:41',
                'mode': 'DEFAULT',
                'brd': 'ff:ff:ff:ff:ff:ff',
                'link_type': 'ether'
            }
        }
    """

    result = {}

    ip_link_re = (
        r'\S*(?P<os_index>\d+):\s(?P<dev>\S+):\s\<(?P<flags_str>\S+)\>\s'
        r'mtu\s(?P<mtu>\d+)\sqdisc\s(?P<qdisc>\S+)\sstate\s(?P<state>\S+)\s'
        r'mode\s(?P<mode>\S+)\sgroup\s(?P<group>\S+)(\s+|\s+qlen\s+(?P<qlen>\d+)\s+)'  # noqa
        r'link\/(?P<link_type>\S+)\s(?P<link>\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2})\s'  # noqa
        r'brd\s(?P<brd>\S{2}:\S{2}:\S{2}:\S{2}:\S{2}:\S{2})'
    )

    for re_match in finditer(ip_link_re, raw_result, DOTALL):
        interface_match = re_match.groupdict()
        interface_match['flags_str'] = interface_match['flags_str'].split(',')
        result[interface_match['os_index']]['mtu'] = int(interface_match['mtu'])  # noqa
        result[interface_match['os_index']]['qlen'] = int(interface_match['qlen'])  # noqa
        result[interface_match['os_index']] = interface_match

    return result


def _parse_ip_route_show(raw_result):
    '''
    Parses the ip route show command output.

    :param str raw_result: Raw output string from command
    :rtype: dict
    :return: The parsed result of the ip route command in a \
        dictionary of the form:

    ::

        {
            '10.20.8.0/21': {
                'dest': '10.20.8.0/21',
                'dev': 'eth0',
                'proto': 'kernel',
                'scope': 'link',
                'src': '10.20.10.1'
            },
            '2.0.255.5': {
                'dest': '2.0.255.5',
                'dev': '31',
                'next_hop': '2.0.40.2',
                'proto': 'zebra'
            },
            '2.0.255.6': {
                'dest': '2.0.255.6',
                'dev': '32',
                'next_hop': '2.0.41.2',
                'proto': 'zebra'
            },
            '2.0.40.0/30': {
                'dest': '2.0.40.0/30',
                'dev': '31',
                'proto': 'kernel',
                'scope': 'link',
                'src': '2.0.40.1'
            },
            'default': {
                'dest': 'default',
                'dev': 'eth0',
                'next_hop': '10.20.8.1'
            }
        }
    '''

    result = {}

    ip_route_re = (
        r'(?P<dest>default|\d+.\d+.\d+.\d+(?:/\d+|))'
        r'(?:\s+via\s(?P<next_hop>\d+.\d+.\d+.\d+)|)'
        r'(?:\s+dev\s(?P<dev>\S+)|)'
        r'(?:\s+proto\s(?P<proto>\S+)|)'
        r'(?:\s+scope\s(?P<scope>\S+)|)'
        r'(?:\s+src\s(?P<src>\d+.\d+.\d+.\d+)|)'
    )

    re_results = finditer(ip_route_re, raw_result)
    if re_results:
        for re_route in re_results:
            partial = re_route.groupdict()
            # remove keys with None value
            for k in partial.keys():
                if partial[k] is None:
                    del partial[k]
            result[partial['dest']] = partial

    return result


def _parse_ip_stats_link_show(raw_result):
    """
    Parse the 'ip -s link show dev <dev>' command raw output.

    :param str raw_result: vtysh raw result string.
    :rtype: dict
    :return: The parsed result of the show interface command in a \
        dictionary of the form:

     ::

        {
            'rx_bytes': 0,
            'rx_packets': 0,
            'rx_errors': 0,
            'rx_dropped': 0,
            'rx_overrun': 0,
            'rx_mcast': 0,
            'tx_bytes': 0,
            'tx_packets': 0,
            'tx_errors': 0,
            'tx_dropped': 0,
            'tx_carrier': 0,
            'tx_collisions': 0,

        }
    """

    show_re = (
        r'.+?RX:.*?\n'
        r'\s*(?P<rx_bytes>\d+)\s+(?P<rx_packets>\d+)\s+(?P<rx_errors>\d+)\s+'
        r'(?P<rx_dropped>\d+)\s+(?P<rx_overrun>\d+)\s+(?P<rx_mcast>\d+)'
        r'.+?TX:.*?\n'
        r'\s*(?P<tx_bytes>\d+)\s+(?P<tx_packets>\d+)\s+(?P<tx_errors>\d+)\s+'
        r'(?P<tx_dropped>\d+)\s+(?P<tx_carrier>\d+)\s+(?P<tx_collisions>\d+)'
    )

    re_result = match(show_re, raw_result, DOTALL)
    result = None

    if (re_result):
        result = re_result.groupdict()
        for key, value in result.items():
            if value is not None:
                if value.isdigit():
                    result[key] = int(value)

    return result


def interface(enode, portlbl, addr=None, up=None, shell=None):
    """
    Configure a interface.

    All parameters left as ``None`` are ignored and thus no configuration
    action is taken for that parameter (left "as-is").

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str portlbl: Port label to configure. Port label will be mapped to
     real port automatically.
    :param str addr: IPv4 or IPv6 address to add to the interface:
     - IPv4 address and netmask to assign to the interface in the form
     ``'192.168.20.20/24'``.
     - IPv6 address and subnets to assign to the interface in the form
     ``'2001::1/120'``.
    :param bool up: Bring up or down the interface.
    :param str shell: Shell name to execute commands.
     If ``None``, use the Engine Node default shell.
    """
    assert portlbl
    port = enode.ports[portlbl]

    if addr is not None:
        assert ip_interface(addr)
        cmd = 'ip addr add {addr} dev {port}'.format(addr=addr, port=port)
        response = enode(cmd, shell=shell)
        assert not response

    if up is not None:
        cmd = 'ip link set dev {port} {state}'.format(
            port=port, state='up' if up else 'down'
        )
        response = enode(cmd, shell=shell)
        assert not response


def sub_interface(enode, portlbl, subint, addr=None, up=None, shell=None):
    """
    Configure a subinterface.

    All parameters left as ``None`` are ignored and thus no configuration
    action is taken for that parameter (left "as-is").
    Sub interfaces can only be configured if the device exists.
    If you want to enable the sub interface, it will enable the interface
    as well.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str portlbl: Port label to configure. Port label will be mapped to
     real port automatically.
    :param str subint: The suffix of the interface.
    :param str addr: IPv4 or IPv6 address to add to the interface:
     - IPv4 address and netmask to assign to the interface in the form
     ``'192.168.20.20/24'``.
     - IPv6 address and subnets to assign to the interface in the form
     ``'2001::1/120'``.
    :param bool up: Bring up or down the interface.
    :param str shell: Shell name to execute commands.
     If ``None``, use the Engine Node default shell.
    """
    assert portlbl
    assert subint
    port = enode.ports[portlbl]

    if addr is not None:
        assert ip_interface(addr)
        cmd = 'ip addr add {addr} dev {port}.{subint}'.format(addr=addr,
                                                              port=port,
                                                              subint=subint)
        response = enode(cmd, shell=shell)
        assert not response

    if up is not None:
        if up:
            interface(enode, portlbl, up=up)

        cmd = 'ip link set dev {port}.{subint} {state}'.format(
            port=port, subint=subint, state='up' if up else 'down'
        )
        response = enode(cmd, shell=shell)
        assert not response


def remove_ip(enode, portlbl, addr, shell=None):
    """
    Remove an IP address from an interface.

    All parameters left as ``None`` are ignored and thus no configuration
    action is taken for that parameter (left "as-is").

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str portlbl: Port label to configure. Port label will be mapped to
     real port automatically.
    :param str addr: IPv4 or IPv6 address to remove from the interface:
     - IPv4 address to remove from the interface in the form
     ``'192.168.20.20'`` or ``'192.168.20.20/24'``.
     - IPv6 address to remove from the interface in the form
     ``'2001::1'`` or ``'2001::1/120'``.
    :param str shell: Shell name to execute commands.
     If ``None``, use the Engine Node default shell.
    """
    assert portlbl
    assert ip_interface(addr)
    port = enode.ports[portlbl]

    cmd = 'ip addr del {addr} dev {port}'.format(addr=addr, port=port)
    response = enode(cmd, shell=shell)
    assert not response


def add_route(enode, route, via, shell=None):
    """
    Add a new static route.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str route: Route to add, an IP in the form ``'192.168.20.20/24'``
     or ``'2001::0/24'`` or ``'default'``.
    :param str via: Via for the route as an IP in the form
     ``'192.168.20.20/24'`` or ``'2001::0/24'``.
    :param shell: Shell name to execute commands. If ``None``, use the Engine
     Node default shell.
    :type shell: str or None
    """
    via = ip_address(via)

    version = '-4'
    if (via.version == 6) or \
            (route != 'default' and ip_network(route).version == 6):
        version = '-6'

    cmd = 'ip {version} route add {route} via {via}'.format(
        version=version, route=route, via=via
    )

    response = enode(cmd, shell=shell)
    assert not response


def add_link_type_vlan(enode, portlbl, name, vlan_id, shell=None):
    """
    Add a new virtual link with the type set to VLAN.

    Creates a new vlan device {name} on device {port}.
    Will raise an exception if value is already assigned.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str portlbl: Port label to configure. Port label will be mapped
     automatically.
    :param str name: specifies the name of the new virtual device.
    :param str vlan_id: specifies the VLAN identifier.
    :param str shell: Shell name to execute commands. If ``None``, use the
     Engine Node default shell.
    """
    assert name
    if name in enode.ports:
        raise ValueError('Port {name} already exists'.format(name=name))

    assert portlbl
    assert vlan_id
    port = enode.ports[portlbl]

    cmd = 'ip link add link {dev} name {name} type vlan id {vlan_id}'.format(
        dev=port, name=name, vlan_id=vlan_id)

    response = enode(cmd, shell=shell)
    assert not response, 'Cannot add virtual link {name}'.format(name=name)

    enode.ports[name] = name


def ip_addr(enode, shell=None):
    """
    Show the ip link table from the swns of a device

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :rtype: dict
    :return: A dictionary as returned by
     :func: topology_lib_ip.parser._parse_ip_addr
    """
    d = None

    # change into the appropriate context on device
    cmd = 'ip netns exec swns ip addr'
    response = enode(cmd, shell=shell)
    d = _parse_ip_addr(response)
    return d


def ip_link(enode, shell=None):
    """
    Show the ip link table from the swns of a device

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :rtype: dict
    :return: A dictionary as returned by
     :func: topology_lib_ip.parser._parse_ip_link
    """
    d = None

    # change into the appropriate context on device
    cmd = 'ip netns exec swns ip link'
    response = enode(cmd, shell=shell)
    d = _parse_ip_link(response)
    return d


def ip_route_show(enode, shell=None):
    """
    Show the ip route table from the swns of a device

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :rtype: dict
    :return: A dictionary as returned by
     :func: topology_lib_ip.parser._parse_ip_route_show
    """
    d = None

    # change into the appropriate context on device
    cmd = 'ip netns exec swns ip route show'
    response = enode(cmd, shell=shell)
    d = _parse_ip_route_show(response)
    return d


def remove_link_type_vlan(enode, name, shell=None):
    """
    Delete a virtual link.

    Deletes a vlan device with the name {name}.
    Will raise an expection if the port is not already present.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str name: specifies the name of the new
     virtual device.
    :param str shell: Shell name to execute commands. If ``None``, use the
     Engine Node default shell.
    """
    assert name
    if name not in enode.ports:
        raise ValueError('Port {name} doesn\'t exists'.format(name=name))

    cmd = 'ip link del link dev {name}'.format(name=name)

    response = enode(cmd, shell=shell)
    assert not response, 'Cannot remove virtual link {name}'.format(name=name)

    del enode.ports[name]


def show_interface(enode, dev, shell=None):
    """
    Show the configured parameters and stats of an interface.

    :param enode: Engine node to communicate with.
    :type enode: topology.platforms.base.BaseNode
    :param str dev: Unix network device name. Ex 1, 2, 3..
    :rtype: dict
    :return: A combined dictionary as returned by both
     :func:`topology_lib_ip.parser._parse_ip_addr_show`
     :func:`topology_lib_ip.parser._parse_ip_stats_link_show`
    """
    assert dev

    cmd = 'ip addr list dev {ldev}'.format(ldev=dev)
    response = enode(cmd, shell=shell)

    first_half_dict = _parse_ip_addr_show(response)

    d = None
    if (first_half_dict):
        cmd = 'ip -s link list dev {ldev}'.format(ldev=dev)
        response = enode(cmd, shell=shell)
        second_half_dict = _parse_ip_stats_link_show(response)

        d = first_half_dict.copy()
        d.update(second_half_dict)
    return d


__all__ = [
    'interface',
    'remove_ip',
    'add_route',
    'add_link_type_vlan',
    'ip_addr',
    'ip_link',
    'ip_route_show',
    'remove_link_type_vlan',
    'sub_interface',
    'show_interface',
]
