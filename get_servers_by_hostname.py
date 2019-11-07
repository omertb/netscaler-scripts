#!/usr/bin/env python3
"""Gets and prints the services bound to a hostname

This script asks for a hostname as input and prints
the bound services, IP addresses, service types and
states in a formatted way as output.

It saves time as for searching which services
the hostname is switched to and the states of
those services.

"""
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import *
from nssrc.com.citrix.netscaler.nitro.resource.config.cs.cspolicy import *
from nssrc.com.citrix.netscaler.nitro.resource.config.cs.cspolicy_binding import *
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_binding import *
from nssrc.com.citrix.netscaler.nitro.resource.config.cs.csvserver import *
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service_lbmonitor_binding import *
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.servicegroup_servicegroupentitymonbindings_binding import *
import requests
from credential import *

# suppress certificate verification warnings
requests.packages.urllib3.disable_warnings()

# read-only user credentials, uncomment and fill in if credential.py file is not available
#USERNAME = "NS USERNAME"
#PASSWORD = "NS PASSWORD"
#NS_IP = "NS IP ADDRESS"

ns_session = nitro_service(NS_IP, "https")
ns_session.certvalidation = False
ns_session.hostnameverification = False
ns_session.login(USERNAME, PASSWORD, 3600)


class colors:
    reset = '\033[0m'
    bold = '\033[01m'
    underline = '\033[04m'

    class fg:
        black = '\033[30m'
        red = '\033[31m'
        green = '\033[32m'
        orange = '\033[33m'
        lightgrey = '\033[37m'
        darkgrey = '\033[90m'

    class bg:
        black = '\033[40m'
        red = '\033[41m'
        green = '\033[42m'


def get_target_vserver(pol_name):
    policy_binding_obj = cspolicy_binding()
    policy_rule_bindings = policy_binding_obj.get(ns_session, policyname=pol_name)
    if hasattr(policy_rule_bindings, 'cspolicy_csvserver_bindings'):  # if True, there exists a VS where policy is bound
        return policy_rule_bindings.cspolicy_csvserver_bindings[0]['action']
    else:
        return None


def get_bound_services(target_virtual_server):
    lbvserver_binding_obj = lbvserver_binding()
    virtual_server = lbvserver_binding_obj.get(ns_session, name=target_virtual_server)
    print("{:^25} {:^24} {:^24} {:^24} {:^44}".format("IP Address", "Port", "Service Type", "Current State", "Cookie"))
    print("{:^25} {:^24} {:^24} {:^24} {:^44}".format("-" * 25, "-" * 24, "-" * 24, "-" * 24, "-" * 44))
    i = 0
    if hasattr(virtual_server, 'lbvserver_servicegroupmember_bindings'):
        for server in virtual_server.lbvserver_servicegroupmember_bindings:
            ip_addr = server['ipv46']
            port = server['port']
            service_type = server['servicetype']
            service_state = server['curstate']
            svc_cookie = server['cookieipport'] if server['cookieipport'] else 'COOKIE INSERT NOT ENABLED!'
            print("{:^25} {:^24} {:^24} {:^24} {:>44}".format(ip_addr, port, service_type, service_state, svc_cookie))

        svc_monitor = servicegroup_servicegroupentitymonbindings_binding.get(ns_session,
                                                                    server['servicegroupname'])

        for monitor in svc_monitor:
            mon_state = monitor.monitor_state
            if mon_state == 'DOWN':  # delete down control to see all monitor status
                ip_addr = monitor.servicegroupentname2.split('?')[1]
                mon_name = monitor.monitor_name
                response = monitor.lastresponse
                print(colors.fg.orange + "* Monitor named \'{}\' for {} is {} || Response: {}".format(mon_name, ip_addr,
                                                                                              mon_state, response)
                      + colors.reset)

    if hasattr(virtual_server, 'lbvserver_service_bindings'):
        for server in virtual_server.lbvserver_service_bindings:
            ip_addr = server['ipv46']
            port = server['port']
            service_type = server['servicetype']
            service_state = server['curstate']
            svc_cookie = server['cookieipport'] if server['cookieipport'] else 'COOKIE INSERT NOT ENABLED!'
            print("{:^25} {:^24} {:^24} {:^24} {:>44}".format(ip_addr, port, service_type, service_state, svc_cookie))

            if service_state == 'DOWN':  # delete down control to see all monitor status
                svc_monitor = service_lbmonitor_binding.get(ns_session, name=server['servicename'])
                for monitor in svc_monitor:
                    print(colors.fg.red + colors.bold + "{:76} {}".format("", "Down Reason: ") +
                          colors.reset + colors.fg.orange + monitor.lastresponse + colors.reset)



def get_vserver_name_ip_addr(pol_name):
    policy_binding_obj = cspolicy_binding()
    policy_rule_bindings = policy_binding_obj.get(ns_session, policyname=pol_name)
    cs_vserver_name = policy_rule_bindings.cspolicy_csvserver_bindings[0]['domain']
    cs_vserver = csvserver()
    cs_vserver_with_attrs = cs_vserver.get(ns_session, name=cs_vserver_name)
    return cs_vserver_name, cs_vserver_with_attrs.ipv46


def chunk_string(string, length):
    return (string[0 + i:length + i] for i in range(0, len(string), length))


def main():
    hostname = input("Enter Hostname: ")
    hostname = "\"" + hostname + "\""

    cs_policies = cspolicy.get(ns_session)

    for policy in cs_policies:
        if hostname in policy.rule:
            policy_name = policy.policyname
            target_vs = get_target_vserver(policy_name)
            if target_vs is not None:  # if None, that policy is not bound to any virtual server
                cs_vserver_name, ip = get_vserver_name_ip_addr(policy_name)
                print("\n" + "/" * 50 + "\\" * 50)
                print("-" * 100)
                print(colors.bold + colors.fg.darkgrey + colors.bg.green,
                      "{:<10}{:>40}{:>10}{:>40}".format(
                          "VSERVER :", cs_vserver_name, "VIP :", ip) + colors.reset)
                print("_" * 100)
                print()
                rule_str_list = list(chunk_string(policy.rule, 50))
                print("{:<50}".format("Policy Rule Content:"), end='')
                print("{:>50}".format(rule_str_list[0]))
                for line in rule_str_list[1:]:
                    print("{:50}{:<50}".format("", line))
                print("_" * 100)
                print()
                get_bound_services(target_vs)
                print("_" * 145)
                print("#" * 145)


if __name__ == "__main__":
    main()
