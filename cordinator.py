#!/usr/bin/env python3

import socket
import json
import requests
from kubernetes import client, config

def get_workers_k8s_api():
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    endpoints = v1.list_namespaced_endpoints('wazuh') #TODO:Get NAMESPACE POD
    workers = []
    for endpoint in endpoints.items:
        if endpoint.metadata.name == 'wazuh-workers':
            subsets = endpoint.subsets
            ips = subsets[0].addresses
            for ip in ips:
                workers.append(ip.ip)
    return workers

def get_workers_wazuh_api():
    namespace = 'wazuh' #TODO:Get NAMESPACE POD
    base_url = 'https://wazuh-manager-master-0.wazuh-cluster.' + namespace + '.svc.cluster.local:55000'
    auth = requests.auth.HTTPBasicAuth('foo', 'bar')
    verify = False
    requests.packages.urllib3.disable_warnings()
    workers = []
    # Request
    url = '{0}{1}'.format(base_url, "/cluster/nodes")
    r = requests.get(url, auth=auth, params=None, verify=False)
    json = r.json()
    items = json['data']['items']
    for worker in items:
        type = worker['type']
        if  type == "worker":
            workers.append(worker['ip'])
    return workers

def get_connections(host):
    connections = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, 9999))
        payload = 'show sess\n'
        s.sendall(bytes(payload.encode()))
        rbytes = s.recv(40960)
        s.close()
        data = str(rbytes).replace("b'", "").replace("'", "").replace(':','').replace('\\n\\n', '').split('\\n')
        datalength = len(data) - 1

        i = 0
        connections = []
        for line in data:
            if datalength > i:
                line = line.split(' ')
                id = line[0]
                connections.append(id)
                i = i + 1
    return connections

def shudown_session(host, connection):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, 9999))
        payload = 'shutdown session ' + connection + '\n'
        payload = payload.encode()
        print(payload)
        s.sendall(payload)
        rbytes = s.recv(40960)
        s.close()

def balance_tcp():
    worker_with_conn = []
    total_connections = 0
    total_workers = 0
    w_from_k8s = get_workers_k8s_api()
    w_from_wazuh = get_workers_wazuh_api()
    #Check counts
    r = 0
    while w_from_k8s != w_from_wazuh:
        print('Workers does not match, retrying...')
        time.sleep(5)
        r = r + 1
        if r > 5:
            print('Workers does not match, exiting...')
            exit(0)
    workers = get_workers_wazuh_api()
    for worker in workers:
        connections = get_connections(worker)
        worker_with_conn.append([worker,connections])
        total_connections = total_connections + len(connections)
        total_workers = total_workers + 1
    #
    fixed_workers_conn = round( total_connections / total_workers)
    #Minimum connections
    if fixed_workers_conn < 1:
        print('Skipping "no_min_conn"')
        return 'no_min_conn'
        exit(0)
    for worker in worker_with_conn:
        connections = worker[1]
        #print(str(connections))
        worker = worker[0]
        worker_connections = len(connections)
        if worker_connections > fixed_workers_conn:
            conn2kill = worker_connections - fixed_workers_conn
            i = 0
            for conn in connections:
                if conn2kill != i :
                    shudown_session(worker,conn)
                    i = i + 1

if __name__ == "__main__":
    balance_tcp()