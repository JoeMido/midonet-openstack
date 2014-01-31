#!/usr/bin/python
# Copyright (c) 2014 Midokura Europe SARL, All Rights Reserved.

from midonetclient.api import MidonetApi
from midonetclient.rule import Rule
import argparse
import inspect
import MySQLdb
import re
import sys

SG_INGRESS_CHAIN = "OS_SG_%s_INGRESS"
SG_EGRESS_CHAIN = "OS_SG_%s_EGRESS"


def add_security_groups_idempotent(api, security_groups, print_result=False,
                                   fix=False):
    """Adds security group chains and ip addr groups, if needed

    Given a list of security groups, this will go through each and create
    the security group chains and ip addr groups associated IFF they are
    missing.
    """
    chain_missing = set()
    addr_groups_missing = set()

    def create_chain_idempotent(name, tenant_id):
        for c in api.get_chains({'tenant_id': tenant_id}):
            if c.get_name() == name:
                # The chain already exists, no need to create
                return
        chain_missing.add(name)
        if fix:
            api.add_chain().tenant_id(sg['tenant_id']).name(name).create()

    ip_addr_groups = api.get_ip_addr_groups()

    def create_ip_addr_group_idempotent(sg_id):
        for ag in ip_addr_groups:
            if ag.get_id() == sg_id:
                #the ip addr group already exists, no need to create
                return
        addr_groups_missing.add(sg_id)
        if fix:
            api.add_ip_addr_group()\
               .id(sg_id)\
               .name("OS_IPG_%s" % sg_id)\
               .create()

    # create the security groups, if they aren't present
    for sg in security_groups:
        create_chain_idempotent("OS_SG_%s_INGRESS" % sg['id'], sg['tenant_id'])
        create_chain_idempotent("OS_SG_%s_EGRESS" % sg['id'], sg['tenant_id'])
        create_ip_addr_group_idempotent(sg['id'])

    if print_result:
        egress_chains_missing = filter(lambda x: "EGRESS" in x, chain_missing)
        ingress_chains_missing = filter(lambda x: "INGRE" in x, chain_missing)
        print "EGRESS chains needed:"
        if egress_chains_missing:
            for n in egress_chains_missing:
                print "   ", n
        else:
            print "    *None*"
        print "INGRESS chains needed:"
        if ingress_chains_missing:
            for n in ingress_chains_missing:
                print "   ", n
        else:
            print "    *None*"
        print "IP_ADD_GROUPS needed:"
        if addr_groups_missing:
            for n in addr_groups_missing:
                print "   ", n
        else:
            print "    *None"

"""
These global dictionaries are useful in printing rules.
The midonet rule object has a lot of getters/setters, and this is a way
to do things to a rule (like print all of its non-null fields) without
having to explicitly invoke all of the getters.
"""
fields = []
# used to filter out getter functions from a rule
getter_regex = re.compile("(is_*|get_*)")
random_meth = ['__init__',
               '__repr__',
               '_ensure_accept',
               '_ensure_content_type',
               'update',
               'create',
               'delete']
rule_attrs = inspect.getmembers(Rule, predicate=inspect.ismethod)
for attr in rule_attrs:
    if not getter_regex.match(attr[0]) and attr[0] not in random_meth:
        fields.append(attr[0])
field_getters = {}
for field in fields:
    getter_regex = re.compile("(is_*|get_*)" + field)
    for attr in rule_attrs:
        if getter_regex.match(attr[0]):
            field_getters.update({field: attr[0]})


def rule_str(rule):
    """Prints the given rule object, even if the dictionary isn't complete.
    """
    rule_str = "rule: "
    for f in fields:
        if rule.get_type() not in ['jump'] and (f is 'jump_chain_id' or
                                                f is 'jump_chain_name'):
            # Only jump rules have these fields.
            continue
        if rule.get_type() not in ['dnat', 'snat'] and (f is 'nat_targets' or
                                                        f is 'flow_action'):
            # Only nat rules have these fields.
            continue
        try:
            val = getattr(rule, field_getters[f])()
            if val:
                if f in ['tp_src', 'tp_dst']:
                    if val['start'] or val['end']:
                        rule_str += (f + ": " + str(val['start']) +
                                     " to " + str(val['end']))
                else:
                    rule_str += f + ": " + str(val) + ", "
        except KeyError:
            continue
    return rule_str


def add_rule_idempotent(api, rules, print_changes=False, fix=False):
    """Adds the given rule if it doesn't exist.
    """
    def get_chain_for_rule(rule):
        chain_name = None
        if rule['direction'] == 'egress':
            chain_name = "OS_SG_%s_EGRESS" % rule['security_group_id']
        else:
            chain_name = "OS_SG_%s_INGRESS" % rule['security_group_id']

        for c in api.get_chains({'tenant_id': rule['tenant_id']}):
            if c.get_name() == chain_name:
                return c
        return None

    rules_to_delete = set()
    rules_to_create = set()

    def create_rule_idempotent(rule):
        chain = get_chain_for_rule(rule)
        if chain is None:
            if print_changes:
                print "chain for rule", rule['id'], "does not exist"
            return
        for r in chain.get_rules():
            props = r.get_properties()
            if 'OS_SG_RULE_ID' not in props:
                print "WTF: no SG rule key"
            if str(props['OS_SG_RULE_ID']) == rule['id']:
                needs_update = False
                if (rule['direction'] == 'ingress' and
                        rule["remote_group_id"] is not None and
                        r.get_ip_addr_group_src() is None):
                    needs_update = True
                elif (rule['direction'] == 'egress' and
                        rule["remote_group_id"] is not None and
                        r.get_ip_addr_group_dst() is None):
                    needs_update = True
                if needs_update:
                    rules_to_delete.add(rule_str(r))
                    if fix:
                        r.delete()
                    break
                else:
                    return

        # still part of create_rule_idempotent
        props = {'OS_SG_RULE_ID': str(rule["id"])}
        src_ipg_id = dst_ipg_id = None
        src_addr = dst_addr = None
        src_port_from = None
        src_port_to = None
        nw_src_addr = None
        nw_src_len = None
        nw_dst_addr = None
        nw_dst_len = None
        dst_port_from = rule["port_range_min"]
        dst_port_to = rule["port_range_max"]
        nw_proto = 1
        if rule['protocol'] == 'tcp':
            nw_proto = 6
        elif rule['protocol'] == 'udp':
            nw_proto = 17
        dl_type = 0x806
        if rule['ethertype'] == 'IPv6':
            dl_type = 0x86DD
        elif rule['ethertype'] == 'IPv4':
            dl_type = 0x0800
        if rule['direction'] == "egress":
            dst_ipg_id = rule["remote_group_id"]
            if rule['remote_ip_prefix']:
                dst_addr = rule["remote_ip_prefix"]
            match_forward_flow = True
        else:
            src_ipg_id = rule["remote_group_id"]
            if rule["remote_ip_prefix"]:
                src_addr = rule["remote_ip_prefix"]
            match_forward_flow = False
        tp_src = {"start": src_port_from, "end": src_port_to}
        tp_dst = {"start": dst_port_from, "end": dst_port_to}
        if nw_proto == 1:  # ICMP
        # Overwrite port fields regardless of the direction
            tp_src = {"start": src_port_from, "end": src_port_from}
            tp_dst = {"start": dst_port_to, "end": dst_port_to}
        if src_addr:
            nw_src_addr, nw_src_len = src_addr.split("/")
        if dst_addr:
            nw_dst_addr, nw_dst_len = dst_addr.split("/")

        new_rule = chain.add_rule()\
                        .properties(props)\
                        .type('accept')\
                        .match_forward_flow(match_forward_flow)\
                        .ip_addr_group_src(src_ipg_id)\
                        .ip_addr_group_dst(dst_ipg_id)\
                        .nw_src_address(nw_src_addr)\
                        .nw_src_length(nw_src_len)\
                        .nw_dst_address(nw_dst_addr)\
                        .nw_dst_length(nw_dst_len)\
                        .nw_proto(nw_proto)\
                        .dl_type(dl_type)\
                        .tp_src(tp_src)\
                        .tp_dst(tp_dst)
        rules_to_create.add(rule_str(new_rule))
        if fix:
            new_rule.create()

    for rule in rules:
        create_rule_idempotent(rule)

    if print_changes:
        print "RULES to delete:"
        if rules_to_delete:
            for r in rules_to_delete:
                print "   ", r
        else:
            print "    *None*"
        print "RULES to create:"
        if rules_to_create:
            for r in rules_to_create:
                print "   ", r
        else:
            print "    *None*"

# Regex to determine if an ip is IPv4 or not.
ip4_reg = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


def add_ips_to_ipaddr_groups_idempotent(api, port_sgs, print_changes=False,
                                        fix=False):
    # create a dictionary of sg ids to lists of ips
    def get_sg_to_ips(data):
        result = dict()
        for entry in data:
            if entry['security_group_id'] not in result:
                result.update({entry['security_group_id']: set()})
            result[entry['security_group_id']].add(entry['ip_address'])
        return result

    def add_port_addrs_idempotent(sg, ips):
        ip_addr_group = None
        for ag in ip_addr_groups:
            if ag.get_id() == sg:
                ip_addr_group = ag
                break

        if ip_addr_group is None:
            # This can happen if we are only in print mode. In this case,
            # the ip_addr_group will not have been created
            if print_changes:
                print "ip addr group", sg, "doesn't exist"
            return
        # why all these sets? sets have efficient membership testing
        # and automatically remove duplicates
        ip_obj_present = set(ip_addr_group.get_addrs())
        ips_present = set(map(lambda x: x.get_addr(), ip_obj_present))
        ips_needed = set(ips)
        ips_to_delete = ips_present - ips_needed
        ips_to_create = ips_needed - ips_present
        if print_changes:
            print "IP_ADDR_GROUP", sg, "changes:"
            if not (ips_to_delete or ips_to_create):
                print "    *None"
            if ips_to_delete:
                print "  to DELETE"
                for ip in ips_to_delete:
                    print "       ", ip
            if ips_to_create:
                print "  to CREATE"
                for ip in ips_to_create:
                    print "       ", ip
        if fix:
            for ip in filter(lambda x: x.get_addr() in ips_to_delete,
                             ip_obj_present):
                ip.delete()
            for ip in ips_to_create:
                ip_obj = None
                if ip4_reg.match(ip):
                    ip_obj = ip_addr_group.add_ipv4_addr()
                else:
                    ip_obj = ip_addr_group.add_ipv6_addr()
                ip_obj.addr(ip).create()

    ip_addr_groups = api.get_ip_addr_groups()
    sg_to_ips = get_sg_to_ips(port_sgs)
    for sg, ips in sg_to_ips.iteritems():
        add_port_addrs_idempotent(sg, ips)


def create_port_chains_idempotent(api, port_sgs, print_result=False,
                                  fix=False):
    """Find/fix errors in port chains.
    """
    def get_port_tenant_ids(data):
        result = dict()
        for entry in data:
            if entry['port_id'] not in result:
                result.update({entry['port_id']: entry['tenant_id']})
        return result

    def get_sg_sets(data):
        result = dict()
        for entry in data:
            if entry['port_id'] not in result:
                result.update({entry['port_id']: []})
            result[entry['port_id']].append(entry['security_group_id'])
        return result

    def get_port_ips(data):
        result = dict()
        for entry in data:
            if entry['port_id'] not in result:
                result.update({entry['port_id']: []})
            result[entry['port_id']].append(entry['ip_address'])
        return result

    def get_port_mac(data):
        result = dict()
        for entry in data:
            if entry['port_id'] not in result:
                result.update({entry['port_id']: entry['mac_address']})
        return result

    # This is not a general rule match function. It is specific to rules
    # on port inbound/outbound chains created by our neutron plugin and will
    # therefore have some leniency on position. We consider the position field
    # to match as long as they are both in the same 'block' of rules.
    def match_rule_in_sg_chain(left, right, position_filter):
        if left.get_type() != right.get_type():
            return False
        for f in fields:
            if (left.get_type() not in ['jump'] and
                    (f is 'jump_chain_id' or f is 'jump_chain_name')):
                continue
            if (left.get_type() not in ['dnat', 'snat'] and
                    (f is 'nat_targets' or f is 'flow_action')):
                continue
            try:
                lval = getattr(left, field_getters[f])()
                rval = getattr(right, field_getters[f])()
                if f == 'position':
                    if position_filter(lval, rval):
                        continue
                    else:
                        return False
                if lval != rval:
                    return False
            except KeyError:
                continue
        return True

    def print_rule(rule):
        rule_str = "rule: "
        for f in fields:
            if (rule.get_type() not in ['jump'] and
                    (f is 'jump_chain_id' or f is 'jump_chain_name')):
                continue
            if (rule.get_type() not in ['dnat', 'snat'] and
                    (f is 'nat_targets' or f is 'flow_action')):
                continue
            try:
                val = getattr(rule, field_getters[f])()
                if val:
                    if f in ['tp_src', 'tp_dst']:
                        if val['start'] or val['end']:
                            rule_str += (f + ": " + val['start'] +
                                         " to " + val['end'])
                    else:
                        rule_str += f + ": " + str(val) + ", "
            except KeyError:
                continue
        return rule_str

    def verify_inbound_chain(in_chain, port_sgs, ips, mac, tenant_id):
        # first scan through all the rules, and delete any that are wrong.
        rules_we_have = set(in_chain.get_rules())
        # The first rules should be the rules corresponding to the ips,
        # then the next is the MAC spoof rule
        rules_we_need = set()
        for ip in ips:
            rules_we_need.add(
                in_chain.add_rule()
                        .nw_src_length(32 if ip4_reg.match(ip) else 64)
                        .nw_src_address(ip)
                        .inv_nw_src(True)
                        .type('drop')
                        .position(1))

        rules_we_need.add(
            in_chain.add_rule()
                    .dl_src(mac)
                    .type('drop')
                    .inv_dl_src(True)
                    .position(len(ips) + 1))

        rules_we_need.add(
            in_chain.add_rule()
                    .match_return_flow(True)
                    .type('accept')
                    .position(len(ips) + 2))

        chains = api.get_chains({'tenant_id': tenant_id})
        for sg in port_sgs:
            chain_name = 'OS_SG_%s_EGRESS' % sg
            chain_id = ''
            for c in chains:
                if c.get_name() == chain_name:
                    chain_id = c.get_id()
            rules_we_need.add(
                in_chain.add_rule()
                        .type('jump')
                        .jump_chain_name(chain_name)
                        .jump_chain_id(chain_id)
                        .position(len(ips) + 3))

        rules_we_need.add(
            in_chain.add_rule()
                    .type('drop')
                    .dl_type(0x0806)
                    .inv_dl_type(True)
                    .position(len(ips) + 3 + len(port_sgs)))

        rule_map_have = set()
        rule_map_need = set()
        rules_to_create = set()
        rules_to_delete = set()

        def pos_filter(lval, rval):
            if rval <= len(ips) and lval <= len(ips):
                return True
            elif (rval <= len(rules_we_need) - 1 and
                  lval <= len(rules_we_need) - 1 and
                  rval >= len(ips) + 3 and
                  rval >= len(ips) + 3):
                return True
            else:
                return rval == lval
            return False

        for rwn in rules_we_need:
            for rwh in rules_we_have:
                if (match_rule_in_sg_chain(rwn, rwh, pos_filter) and
                        rwh not in rule_map_have):
                    rule_map_have.add(rwh)
                    rule_map_need.add(rwn)

        # rule_map is now a set of rules we have that we need
        rules_to_delete = rules_we_have - rule_map_have
        rules_to_create = rules_we_need - rule_map_need
        if print_result:
            print "Port Inbound Chain", in_chain.get_name(), "rules to create"
            if rules_to_create:
                for r in rules_to_create:
                    print "   ", rule_str(r)
            else:
                print "    *None"
            print "Port Inbound Chain", in_chain.get_name(), "rules to delete"
            if rules_to_delete:
                for r in rules_to_delete:
                    print "   ", rule_str(r)
            else:
                print "    *None"
        if fix:
            [r.create() for r in rules_to_create]
            [r.delete() for r in rules_to_delete]

    def verify_outbound_chain(out_chain, port_sgs, ips, mac, tenant_id):
        rules_we_have = set(out_chain.get_rules())
        rules_we_need = set()
        for r in rules_we_have:
            print_rule(r)

        rules_we_need.add(
            out_chain.add_rule()
                     .match_return_flow(True)
                     .type('accept')
                     .position(1))

        chains = api.get_chains({'tenant_id': tenant_id})
        for sg in port_sgs:
            chain_name = 'OS_SG_%s_INGRESS' % sg
            chain_id = ''
            for c in chains:
                if c.get_name() == chain_name:
                    chain_id = c.get_id()
            rules_we_need.add(
                out_chain.add_rule()
                         .type('jump')
                         .jump_chain_name(chain_name)
                         .jump_chain_id(chain_id)
                         .position(2))

        rules_we_need.add(
            out_chain.add_rule()
                     .type('drop')
                     .dl_type(0x0806)
                     .inv_dl_type(True)
                     .position(len(port_sgs) + 2))

        rule_map_have = set()
        rule_map_need = set()
        rules_to_create = set()
        rules_to_delete = set()

        def pos_filter(lval, rval):
            if (1 < rval < len(port_sgs) and
                    1 < lval < len(port_sgs)):
                return True
            else:
                return rval == lval
            return False

        for rwn in rules_we_need:
            for rwh in rules_we_have:
                if (match_rule_in_sg_chain(rwn, rwh, pos_filter)
                        and rwh not in rule_map_have):
                    rule_map_have.add(rwh)
                    rule_map_need.add(rwn)

        # rule_map is now a set of rules we have that we need
        rules_to_delete = rules_we_have - rule_map_have
        rules_to_create = rules_we_need - rule_map_need
        if print_result:
            print "Outbound Chain", out_chain.get_name(), "rules to create"
            if rules_to_create:
                for r in rules_to_create:
                    print "   ", rule_str(r)
            else:
                print "    *None"
            print "Outbound Chain", out_chain.get_name(), "rules to delete"
            if rules_to_delete:
                for r in rules_to_delete:
                    print "   ", rule_str(r)
            else:
                print "    *None"
        if fix:
            [r.create() for r in rules_to_create]
            [r.delete() for r in rules_to_delete]

    def create_chains_idempotent(port_id, sgs, tenant_id, port_ips, mac):
        mido_port = api.get_port(port_id)
        in_chain = None
        out_chain = None
        if not mido_port:
            if print_result:
                print "the port", port_id, "doesn't even exist..."
            return
        in_chain_id = mido_port.get_inbound_filter_id()
        if in_chain_id is None:
            if print_result:
                print "inbound filter does not exist for port", port_id
            if fix:
                in_chain = api.add_chain()\
                              .tenant_id(tenant_id)\
                              .name("OS_PORT_%s_INBOUND" % port_id)\
                              .create()
        else:
            in_chain = api.get_chain(in_chain_id)

        out_chain_id = mido_port.get_outbound_filter_id()
        if out_chain_id is None:
            if print_result:
                print "outbound filter does not exist for port", port_id
            if fix:
                out_chain = api.add_chain()\
                               .tenant_id(tenant_id)\
                               .name("OS_PORT_%s_OUTBOUND" % port_id)\
                               .create()
        else:
            out_chain = api.get_chain(out_chain_id)

        if in_chain:
            verify_inbound_chain(in_chain, sgs, port_ips, mac, tenant_id)
        if out_chain:
            verify_outbound_chain(out_chain, sgs, port_ips, mac, tenant_id)

    ports = get_sg_sets(port_sgs)
    port_tenants = get_port_tenant_ids(port_sgs)
    port_ips = get_port_ips(port_sgs)
    port_macs = get_port_mac(port_sgs)
    for k, v in ports.iteritems():
        create_chains_idempotent(k, v, port_tenants[k], port_ips[k],
                                 port_macs[k])


def _execute_query(cursor, query):
    """Execute the given query using the cursor, and return the rows
    including the column names.
    """
    cursor.execute(query)
    rows = cursor.fetchall()
    out_rows = []
    for row in rows:
        item = {}
        for i, val in enumerate(row):
            item[cursor.description[i][0]] = val
        out_rows.append(item)
    return out_rows


def get_security_groups(cursor):
    return _execute_query(cursor,
                          "SELECT id, tenant_id FROM securitygroups")


def get_security_group_rules(cursor):
    return _execute_query(
        cursor,
        """\
            SELECT id, tenant_id, security_group_id, remote_group_id,
                   direction, ethertype, protocol, port_range_min,
                   port_range_max, remote_ip_prefix
            FROM securitygrouprules;
        """)


def get_sg_port_ips(cursor):
    return _execute_query(
        cursor,
        """\
        SELECT sgpb.security_group_id, sgpb.port_id, ia.ip_address,
               fip.floating_ip_address, p.tenant_id, p.mac_address
        FROM securitygroupportbindings as sgpb
            JOIN ports AS p ON sgpb.port_id = p.id
            LEFT JOIN ipallocations AS ia ON p.id = ia.port_id
            LEFT JOIN floatingips AS fip ON fip.fixed_port_id = p.id;
        """)


def main():

    parser = argparse.ArgumentParser(description="Dump Neutron SQL data")
    parser.add_argument('-s', '--server', default='localhost',
                        help='Neutron DB host')
    parser.add_argument('-p', '--port', default=3306, type=int,
                        help='Neutron DB port')
    parser.add_argument('-u', '--user', default='root',
                        help='Neutron DB user')
    parser.add_argument('-w', '--password', default='password',
                        help='Neutron DB password')
    parser.add_argument('-d', '--database', default='neutron_midonet',
                        help='Neutron DB name')
    parser.add_argument('-U', '--midonet_user', default='admin',
                        help='midonet API user name')
    parser.add_argument('-P', '--midonet_password', default='havana',
                        help='midonet API password')
    parser.add_argument('-r', '--midonet_project', default='admin',
                        help='midonet project id')
    parser.add_argument('-H', '--midonet_api_host', default='localhost',
                        help='midonet api host ip')
    parser.add_argument('-o', '--midonet_api_port', default='8081',
                        help='midonet api host ip')
    parser.add_argument('-f', '--fix', action='store_true', default=False,
                        help='fix problems found')
    parser.add_argument('-i', '--print_result', action='store_true',
                        default=False, help='print problems found')
    args = vars(parser.parse_args())

    db = MySQLdb.connect(host=args['server'], port=args['port'],
                         user=args['user'], passwd=args['password'],
                         db="neutron_midonet")
    cursor = db.cursor()

    mido_api = MidonetApi('http://' + args['midonet_api_host'] + ":" +
                          args['midonet_api_port'] + '/midonet-api',
                          args['midonet_user'], args['midonet_password'],
                          args['midonet_project'])

    sgs = get_security_groups(cursor)
    rules = get_security_group_rules(cursor)
    for rule in rules:
        print rule
    addrs = get_sg_port_ips(cursor)

    add_security_groups_idempotent(mido_api, sgs, args['print_result'],
                                   args['fix'])
    add_rule_idempotent(mido_api, rules, args['print_result'], args['fix'])
    add_ips_to_ipaddr_groups_idempotent(mido_api, addrs, args['print_result'],
                                        args['fix'])
    create_port_chains_idempotent(mido_api, addrs, args['print_result'],
                                  args['fix'])

if __name__ == "__main__":
    main()
