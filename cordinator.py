#!/usr/bin/env python3

import logging
import re
import socket
from time import sleep

import requests
import six
from kubernetes import client, config

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(asctime)s] %(pathname)s:%(lineno)d %(funcName)s %(levelname)s %(message)s','%m-%d %H:%M:%S')
ch.setFormatter(formatter)
logger.addHandler(ch)


# send socket
def send_to_socket(host, msg):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, 9999))
        s.send(six.b(msg + '\n'))
        file_handle = s.makefile()
    except socket.timeout:
        return False
    else:
        try:
            data = file_handle.read().splitlines()
        except socket.timeout:
            return False
        else:
            logger.debug(("message sent to HOST:SOCKET " + host + ":9999 " + str(msg)))
            logger.debug("data receive from SOCKET " + host + " " + str(data))
            return data
    finally:
        s.close()


# retorna IP de endpoints del servicio wazuh-workers
def get_workers_k8s_api():
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    try:
        endpoints = v1.list_namespaced_endpoints("wazuh")  # TODO:Get NAMESPACE POD
        workers = []
        for endpoint in endpoints.items:
            if endpoint.metadata.name == 'wazuh-workers':
                subsets = endpoint.subsets
                ips = subsets[0].addresses
                for ip in ips:
                    workers.append(ip.ip)
        print("Total Workers from K8s API: " + str(len(workers)))
    except Exception as e:
        print(str(e))
        exit(1)
    return workers


# Retorna lista de IP de workers del servicio API de Wazuh
def get_workers_wazuh_api():
    namespace = 'wazuh'  # TODO:Get NAMESPACE POD
    base_url = 'https://wazuh-manager-master-0.wazuh-cluster.' + namespace + '.svc.cluster.local:55000'
    auth = requests.auth.HTTPBasicAuth('foo', 'bar')  # TODO Get API Credentials
    requests.packages.urllib3.disable_warnings()
    workers = []
    # Request
    url = '{0}{1}'.format(base_url, "/cluster/nodes")
    r = requests.get(url, auth=auth, params=None, verify=False)
    json = r.json()
    items = json['data']['items']
    for worker in items:
        type = worker['type']
        if type == "worker":
            workers.append(worker['ip'])
    print("Total Workers from Wazuh API: " + str(len(workers)))
    return workers


# Retorna sumatoria de bytes enviados y recibidos por una sesion TCP
def get_traffic(host, connection):
    traffic = 0
    rdata = send_to_socket(host, "show sess " + connection)
    rawtotals = re.findall(r"(total=\d+)", str(rdata))
    for total in rawtotals:
        tbytes = int(total.replace("total=", ""))
        traffic = traffic + tbytes
    return traffic


# Retorna lista de conexiones,trafico de un worker
def get_connections(host):
    rdata = send_to_socket(host, "show sess")
    datalength = len(rdata) - 1
    print("Conections: " + str(datalength))
    i = 0
    connections = []
    for line in rdata:
        if datalength > i:
            line = line.split(' ')
            id = str(line[0]).replace(":", "")
            print(str(id))
            traffic = get_traffic(host, id)
            connections.append([id, traffic])
            i = i + 1
    print(connections)
    exit(1)
    return connections


# Elimina una sesion pasando ID.
def shudown_session(host, connection):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, 9999))
        payload = 'shutdown session ' + connection + '\n'
        payload = payload.encode()
        print(payload)
        s.sendall(payload)
        rbytes = s.recv(40960)
        s.close()


# Establece el estado de un worker ( via HAPROXY )
def set_server_state(host, state):
    if state == "ready" or state == "drain" or state == "maint":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, 9999))
            payload = "set server l1/srv1 state " + state + "\n"
            payload = payload.encode()
            print(payload)
            s.sendall(payload)
            rbytes = s.recv(40960)
            s.close()
    else:
        print("State no supported. Exiting...")
        exit(1)


'''
Balanceo teniendo en cuenta la cantidad de sesiones TCP ( agentes ) / Workers"
'''


def tcp_sessions():
    worker_with_conn = []
    total_connections = 0
    total_workers = 0
    workers = get_workers_wazuh_api()
    w_from_k8s = len(get_workers_k8s_api())
    w_from_wazuh = len(workers)

    retry = 0
    while w_from_k8s != w_from_wazuh:
        print('Workers does not match, retrying...')
        sleep(5)
        retry = retry + 1
        if retry > 5:
            print('Workers does not match, exiting...')
            exit(0)

    for worker in workers:
        connections = []
        connections_with_load = get_connections(worker)
        for connection_with_load in connections_with_load:
            connection = connection_with_load[0]
            connections.append(connection)
        worker_with_conn.append([worker, connections])
        total_connections = total_connections + len(connections)
        total_workers = total_workers + 1

    fixed_workers_conn = round(total_connections / total_workers)
    print("Total connections: " + str(total_connections))
    print("Fixed connections per worker: " + str(fixed_workers_conn))
    # Minimum connections
    if fixed_workers_conn < 1:
        print('Skipping "no_min_conn"')
        return 'no_min_conn'
        exit(0)

    wait = False
    for worker in worker_with_conn:
        connections = worker[1]
        worker = worker[0]
        worker_connections = len(connections)
        if worker_connections > fixed_workers_conn + 1:
            wait = True
            conn2kill = worker_connections - fixed_workers_conn
            i = 0
            set_server_state(worker, "drain")
            for conn in connections:
                if conn2kill != i:
                    shudown_session(worker, conn)
                    i = i + 1

    if wait:
        print("Waiting 60s to renew connections...")
        sleep(60)
        for worker in worker_with_conn:
            worker = worker[0]
            set_server_state(worker, "ready")
    else:
        print("Nothing to do, bye...")


# Balanceo teniendo en cuenta la cantidad de sesiones TCP ( agentes ) / Workers, ordenando sesiones por trafico.
def tcp_sessions_and_load():
    worker_with_conn = []
    total_connections = 0
    total_workers = 0
    workers = get_workers_wazuh_api()
    w_from_k8s = len(get_workers_k8s_api())
    w_from_wazuh = len(workers)

    retry = 0
    while w_from_k8s != w_from_wazuh:
        print('Workers does not match, retrying...')
        sleep(5)
        retry = retry + 1
        if retry > 5:
            print('Workers does not match, exiting...')
            exit(0)

    for worker in workers:
        connections = []
        connections_with_load = get_connections(worker)
        for connection_with_load in connections_with_load:
            connection = connection_with_load[0]
            connections.append(connection)
        worker_with_conn.append([worker, connections])
        total_connections = total_connections + len(connections)
        total_workers = total_workers + 1

    fixed_workers_conn = round(total_connections / total_workers)
    print("Total connections: " + str(total_connections))
    print("Fixed connections per worker: " + str(fixed_workers_conn))
    if fixed_workers_conn < 1:
        print('Skipping "no_min_conn"')
        return 'no_min_conn'
        exit(0)

    wait = False
    for worker in worker_with_conn:
        connections = worker[1]
        worker = worker[0]
        worker_connections = len(connections)
        if worker_connections > fixed_workers_conn + 1:
            wait = True
            conn2kill = worker_connections - fixed_workers_conn
            i = 0
            set_server_state(worker, "drain")
            for conn in connections:
                # Mata posiciones impares.
                if conn2kill != i and i % 2 != 0:
                    shudown_session(worker, conn)
                    i = i + 1

                    ###pesos 

    if wait:
        print("Waiting 300s to renew connections...")
        sleep(300)
        for worker in worker_with_conn:
            worker = worker[0]
            set_server_state(worker, "ready")
    else:
        print("Nothing to do, bye...")


if __name__ == "__main__":
    tcp_sessions()
