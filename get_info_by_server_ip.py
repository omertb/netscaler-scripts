#!/usr/bin/env python3
"""Gets and prints the virtual servers and
content switching policies bound to a server IP address.

The script accepts IP address as input;
and prints bound content switching policies
with hit numbers as output.

"""
import requests
import json
from credential import *
# Nitro-sdk library is not needed

# suppress certificate verification warnings
requests.packages.urllib3.disable_warnings()

# read-only user credentials, uncomment and fill in if credential.py file is not available
# USERNAME = "USERNAME"
# PASSWORD = "PASSWORD"
# NS_IP = "Netscaler IP ADDRESS"


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


class ServerBindings:
    def __init__(self, username, password, ns_ip):
        self.headers = {
            'X-NITRO-USER': username,
            'X-NITRO-PASS': password
        }
        self.ns_ip = ns_ip

    def get_bindings_by_server_ip(self, server_ip) -> dict:
        url = "https://{}/nitro/v1/config/server_binding/{}".format(self.ns_ip, server_ip)
        response = requests.request("GET", url, headers=self.headers, verify=False)
        response_dict = json.loads(response.text)

        if response_dict['errorcode'] == 0:
            return response_dict['server_binding'][0]

    def get_vs_by_svc_name(self, svc_name) -> list:
        url = "https://{}/nitro/v1/config/svcbindings".format(self.ns_ip)
        querystring = "args=servicename:{}".format(svc_name)
        response = requests.request("GET", url, headers=self.headers, params=querystring, verify=False)

        response_dict = json.loads(response.text)
        bound_vservers = []
        for service in response_dict['svcbindings'][1:]:
            bound_vservers.append(service['vservername'])
        return bound_vservers

    def get_vs_by_grp_name(self, svc_grp_name) -> list:
        url = "https://{}/nitro/v1/config/servicegroupbindings".format(self.ns_ip)
        querystring = "args=servicegroupname:{}".format(svc_grp_name)
        response = requests.request("GET", url, headers=self.headers, params=querystring, verify=False)

        response_dict = json.loads(response.text)
        bound_vservers = []
        for service in response_dict['servicegroupbindings'][1:]:
            bound_vservers.append(service['vservername'])
        return bound_vservers

    def get_bindings_by_vs(self, vserver_name) -> list:
        url = "https://{}/nitro/v1/config/lbvserver_csvserver_binding/{}".format(self.ns_ip, vserver_name)
        response = requests.request("GET", url, headers=self.headers, verify=False)
        response_dict = json.loads(response.text)
        return response_dict['lbvserver_csvserver_binding']  # policy-target LBV list
        # And each list item is a dictionary with keys: cachevserver, policyname, hits

    def get_cs_policy_rule_content(self, policy_name) -> str:
        url = "https://{}/nitro/v1/config/cspolicy/{}".format(self.ns_ip, policy_name)
        response = requests.request("GET", url, headers=self.headers, verify=False)
        response_dict = json.loads(response.text)
        return response_dict['cspolicy'][0]['rule']


def chunk_string(string, length):
    return (string[0 + i:length + i] for i in range(0, len(string), length))


def main():
    ip_addr = input("Enter IP Address: ")
    sb = ServerBindings(USERNAME, PASSWORD, NS_IP)
    bindings_dict = sb.get_bindings_by_server_ip(ip_addr)
    if bindings_dict is None:
        print("No such resource!")
        return
    svc_list = []
    bound_vs_list = []
    print("\n" + "/" * 45 + "\\" * 45)
    print("_" * 90)
    print(colors.bold + colors.fg.darkgrey + colors.bg.green +
          "{:<45}{:>45}".format("Server IP Address:", ip_addr) + colors.reset)
    print("-" * 90)
    print("{:^45} {:^14} {:^14} {:^14}".format("Service/Group Name", "Service Type", "Server Port", "Server State"))
    print("{:^45} {:^14} {:^14} {:^14}".format("-" * 45, "-" * 14, "-" * 14, "-" * 14))

    if 'server_servicegroup_binding' in bindings_dict:
        svc_list.extend(bindings_dict['server_servicegroup_binding'])
    if 'server_service_binding' in bindings_dict:
        svc_list.extend(bindings_dict['server_service_binding'])

    for svc in svc_list:
        if 'servicegroupname' in svc:
            svc_name = svc['servicegroupname']
            bound_vs = sb.get_vs_by_grp_name(svc_name)  # returns vserver names list
        if 'servicename' in svc:
            svc_name = svc['servicename']
            bound_vs = sb.get_vs_by_svc_name(svc_name)  # returns vserver names list

        svc_type = svc['svctype']
        svr_port = svc['port']
        svr_state = svc['svrstate']
        print("{:<45} {:^14} {:^14} {:^14}".format(svc_name, svc_type, svr_port, svr_state))
        print(colors.bold + colors.fg.orange + "{:>90}{}".format(" └──> ", ", ".join(bound_vs)) + colors.reset)
        bound_vs_list.extend(bound_vs)

    print("_" * 130)
    print("#" * 130)
    for vs in bound_vs_list:
        print(colors.bold + colors.fg.orange)
        print("_" * 130)
        print("{:<65}{:>65}".format("LB Virtual Server Name: ", vs))
        print("-" * 130)
        print(colors.reset)
        policy_target_list = sb.get_bindings_by_vs(vs)
        print("{:^30} {:^30} {:^17} {:^50}".format("CS VS Name", "Policy Name", "Policy Hits", "Policy Content"))
        print("{:^30} {:^30} {:^17} {:^50}".format("-" * 30, "-" * 30, "-" * 17, "-" * 50))
        for policy_binding in policy_target_list:
            policy_name = policy_binding['policyname']
            policy_hits = policy_binding['hits']
            cs_vs = policy_binding['cachevserver']

            rule = sb.get_cs_policy_rule_content(policy_name)
            rule_str_list = list(chunk_string(rule, 50))
            print("{:<30} {:<30} {:>17} {:<50}".format(cs_vs, policy_name, policy_hits, rule_str_list[0]))
            for line in rule_str_list[1:]:
                print("{:80}{:<50}".format("", line))
        print("#" * 130)


if __name__ == "__main__":
    main()
