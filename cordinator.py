#!/usr/bin/env python3

import socket
import json
import requests

base_url = 'https://IP:55000'
auth = requests.auth.HTTPBasicAuth('foo', 'bar')
verify = False
requests.packages.urllib3.disable_warnings()

# Request
url = '{0}{1}'.format(base_url, "/")
r = requests.get(url, auth=auth, params=None, verify=False)
print(str(r))
exit(1)

print(json.dumps(r.json(), indent=4, sort_keys=True))
print("Status: {0}".format(r.status_code))

#Reemplazar utilizando la API de Wazuh/Kubernetes 
WORKERS = ['192.168.23.123', '192.168.5.11']
#WORKERS = ['192.168.23.123','192.168.0.28','192.168.29.89']


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

def get_workers():
    workers = WORKERS
    return workers

def balance_tcp():
    worker_with_conn = []
    total_connections = 0
    total_workers = 0
    workers = get_workers()
    
    for worker in workers:
        connections = get_connections(worker)
        worker_with_conn.append([worker,connections])
        total_connections = total_connections + len(connections)
        total_workers = total_workers + 1
    
    #roundrobin
    fixed_workers_conn = round( total_connections / total_workers)
    print(str(fixed_workers_conn))

    for worker in worker_with_conn:
        connections = worker[1]
        print(str(connections))
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
