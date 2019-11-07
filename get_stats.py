#!/usr/bin/env python3
"""Gets and prints System Resource Utilization,
HTTP and TCP Stats for Citrix Netscaler.

"""
import requests
import json
from credential import *
# Nitro-sdk library is not needed

# suppress certificate verification warnings
requests.packages.urllib3.disable_warnings()

# read-only user credentials, uncomment and fill in if credential.py file is not available
#USERNAME = "USERNAME"
#PASSWORD = "PASSWORD"
#NS_IP = "Netscaler IP Address"


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

cred_headers = {
    'X-NITRO-USER': USERNAME,
    'X-NITRO-PASS': PASSWORD
}

def get_stats(of_item) -> dict:
    url = "https://{}/nitro/v1/stat/{}".format(NS_IP, of_item)
    response = requests.request("GET", url, headers=cred_headers, verify=False)
    response_dict = json.loads(response.text)
    return response_dict[of_item]


def main():
    print(colors.bold + colors.fg.orange + "Netscaler System Stats:" + colors.reset)
    print("-" * 52)
    ns_stats = get_stats("ns")
    mgmt_cpu_usage = ns_stats['mgmtcpuusagepcnt']  # float
    pkt_cpu_usage = ns_stats['pktcpuusagepcnt']  # float
    mem_usage = ns_stats['memusagepcnt']  # float
    rx_in_mbps = ns_stats['rxmbitsrate']  # int
    tx_in_mbps = ns_stats['txmbitsrate']  # int
    ha_state = ns_stats['hacurstate']  # str

    http_req_rate = ns_stats['httprequestsrate']  # int
    http_res_rate = ns_stats['httpresponsesrate']  # int
    http_rx_req_bytes_rate = ns_stats['httprxrequestbytesrate']  # int
    http_rx_res_bytes_rate = ns_stats['httprxresponsebytesrate']  # int

    tcp_cur_client_conn = ns_stats['tcpcurclientconn']  # str
    tcp_cur_client_conn_established = ns_stats['tcpcurclientconnestablished']  # str
    tcp_cur_server_conn = ns_stats['tcpcurserverconn']  # str
    tcp_cur_server_conn_established = ns_stats['tcpcurserverconnestablished']  # str

    ssl_transaction_rate = ns_stats['ssltransactionsrate']  # int
    ssl_session_hits_rate = ns_stats['sslsessionhitsrate']  # int
    cache_hits_rate = ns_stats['cachehitsrate']  # int
    cache_total_hits = ns_stats['cachetothits']  # str

    print("_" * 52)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Management CPU Usage", ":") + colors.reset
          + colors.fg.green + "{:>10} %".format(round(mgmt_cpu_usage, 2)) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Packet CPU Usage", ":") + colors.reset + colors.fg.green
          + "{:>10} %".format(round(pkt_cpu_usage, 2)) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Memory Usage", ":") + colors.reset + colors.fg.green
          + "{:>10} %".format(round(mem_usage, 2)) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("RX Traffic", ":") + colors.reset + colors.fg.green
          + "{:>10} Mbps".format(rx_in_mbps) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("TX Traffic", ":") + colors.reset + colors.fg.green
          + "{:>10} Mbps".format(tx_in_mbps) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("SSL Transactions Rate", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(ssl_transaction_rate) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("SSL Session Hits Rate", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(ssl_session_hits_rate) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Cache Hits Rate", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(cache_hits_rate) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Cache Total Hits", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(cache_total_hits) + colors.reset)
    print("-" * 52)

    print(colors.bold + colors.fg.orange + colors.underline + "HTTP Stats:" + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("HTTP Request Rate", ":") + colors.reset + colors.fg.green
          + "{:>10}".format(http_req_rate) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("HTTP Response Rate", ":") + colors.reset + colors.fg.green
          + "{:>10}".format(http_res_rate) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("HTTP Request Bytes Rate", ":") + colors.reset
          + colors.fg.green + "{:>10} KBps".format(round(http_rx_req_bytes_rate/1024, 2)) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("HTTP Response Bytes Rate", ":") + colors.reset
          + colors.fg.green + "{:>10} KBps".format(round(http_rx_res_bytes_rate / 1024, 2)) + colors.reset)
    print("-" * 52)

    print(colors.bold + colors.fg.orange + colors.underline + "TCP Stats:" + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Current Client Connections", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(tcp_cur_client_conn) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Current Server Connections", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(tcp_cur_server_conn) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Established Client Connections", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(tcp_cur_client_conn_established) + colors.reset)
    print(colors.fg.red + colors.bold + "{:<40}{:>2}".format("Established Server Connections", ":") + colors.reset
          + colors.fg.green + "{:>10}".format(tcp_cur_server_conn_established) + colors.reset)
    print("-" * 52)


if __name__ == "__main__":
    main()