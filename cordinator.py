#!/usr/bin/env python3

import socket
import json
import requests
from kubernetes import client, config

#config = kubernetes.client.Configuration()
#config.host = "https://kubernetes.default.svc.cluster.local/"
#config.verify_ssl = False
#v1 = kubernetes.client.CoreV1Api(kubernetes.client.ApiClient(config))

config.load_incluster_config()
v1 = client.CoreV1Api()

pods = v1.list_namespaced_endpoints('wazuh')
for pod in pods.items:
    print(str(pod))
    exit(1)



def get_workers_wazuh_api():
    base_url = 'https://wazuh-manager-master-0.wazuh-cluster.wazuh.svc.cluster.local:55000'
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

        for conn in connections:
            print(str(worker)+' ' +str(conn))

        if worker_connections > fixed_workers_conn:
            conn2kill = worker_connections - fixed_workers_conn
            i = 0
            for conn in connections:
                if conn2kill != i :
                    shudown_session(worker,conn)
                    i = i + 1

if __name__ == "__main__":
    balance_tcp()
    #workers = get_workers_wazuh_api(master)
