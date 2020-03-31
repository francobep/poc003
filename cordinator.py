#!/usr/bin/env python3

import logging
import re
import socket
import requests
import six
import argparse
from time import sleep
from kubernetes import client, config


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lbmode",
                        action="store",
                        type=int,
                        help="1 *Default => TCP Sessions, 2 => TCP Sessions with Network Load",
                        default=1,
                        dest="lbmode")
    parser.add_argument("--v",
                        "-v",
                        action="store",
                        type=int,
                        help="1 *Default => INFO, 2 => Warning, 3 => DEBUG",
                        default=1,
                        choices={1, 2, 3},
                        dest="verbosity_level")
    parser.add_argument("--force",
                        action="store_true",
                        help="Force set max_conn to workers",
                        dest="force")
    parser.add_argument("--dryrun",
                        action="store_true",
                        help="Dry run mode.",
                        dest="dryrun")
    args = parser.parse_args()
    logging.debug(vars(args))
    return args


def set_logger(verbosity_level):
    log_format = "%(asctime)s %(levelname)s: %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logger = logging.getLogger()
    level = logging.INFO
    if verbosity_level == 2:
        level = logging.WARNING
    elif verbosity_level == 3:
        level = logging.DEBUG
    logger.setLevel(level)

    console = logging.StreamHandler()
    console.setLevel(level)
    formatter = logging.Formatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    console.setFormatter(formatter)
    if logger.hasHandlers():
        logger.handlers.clear()
    logger.addHandler(console)


'''
send socket
'''


def sendto_socket(host, msg):
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
            logging.info("Sent MSG to HAP Runtime API OK!")
            logging.debug(("sent to " + host + ":9999 " + str(msg)))
            logging.debug("data from " + host + " " + str(data))
            return data
    finally:
        s.close()


'''
retorna IP de endpoints del servicio wazuh-workers
'''


def get_workers_k8s_api():
    logging.info("Getting workers from K8's API")
    config.load_incluster_config()
    v1 = client.CoreV1Api()
    try:
        endpoints = v1.list_namespaced_endpoints("wazuh")  # TODO:Get POD NAMESPACE
        workers = []
        for endpoint in endpoints.items:
            if endpoint.metadata.name == 'wazuh-workers':
                subsets = endpoint.subsets
                ips = subsets[0].addresses
                for ip in ips:
                    workerip = ip.ip
                    workers.append(workerip)
                    logging.debug("Found Worker from K8's API => " + str(workerip))
        logging.info("Total Workers from K8s API = " + str(len(workers)))
        return workers
    except Exception as e:
        logging.error(e)
        return False


'''
Retorna lista de IP de workers del servicio API de Wazuh
'''


def get_workers_wazuh_api():
    logging.info("Getting workers from Wazuh API")
    namespace = 'wazuh'  # TODO:Get NAMESPACE POD
    base_url = 'https://wazuh-manager-master-0.wazuh-cluster.' + namespace + '.svc.cluster.local:55000'
    auth = requests.auth.HTTPBasicAuth('foo', 'bar')  # TODO Get API Credentials
    requests.packages.urllib3.disable_warnings()
    workers = []
    # Request
    url = '{0}{1}'.format(base_url, "/cluster/nodes")
    try:
        r = requests.get(url, auth=auth, params=None, verify=False)
        response = r.json()
    except requests.exceptions as e:
        logging.error(e)
        return False
    else:
        items = response['data']['items']
        for worker in items:
            wazuhtype = worker['type']
            if wazuhtype == "worker":
                workers.append(worker['ip'])
                logging.debug("Found Worker from Wazuh API = " + str(worker['ip']))
        logging.info("Total Workers from Wazuh API: " + str(len(workers)))
        return workers


'''
Retorna sumatoria de bytes enviados y recibidos por una sesion TCP
'''


def get_traffic(host, conn_id):
    traffic = 0
    logging.debug("Getting connection traffic " + host + ":9999:" + conn_id)
    rdata = sendto_socket(host, "show sess " + conn_id)
    rawtotals = re.findall(r"(total=\d+)", str(rdata))
    for total in rawtotals:
        if traffic == 0:
            logging.debug("Connection " + host + ":9999:" + conn_id + " bytes inbound " + str(total))
        else:
            logging.debug("Connection " + host + ":9999:" + conn_id + " bytes outbound " + str(total))
        tbytes = int(total.replace("total=", ""))
        traffic = traffic + tbytes
    return traffic


'''
Retorna lista de conexiones,trafico de un worker
'''


def get_connections(host):
    logging.info("Getting current agents TCP connections from HAP")
    rdata = sendto_socket(host, "show sess")
    datalength = len(rdata) - 2
    logging.info("Current TCP agent connections => " + str(datalength) + " on Worker " + host)
    connections = []
    logging.info("Getting Traffic from TCP agent connection")
    hostname = socket.gethostname()
    ipaddr = str(socket.gethostbyname(hostname))
    for line in rdata:
        line = line.split(' ')
        if line != ['']:
            src_con = str(line[2]).replace("src=", "").split(":")
            src_ipaddr = src_con[0]
            logging.debug("ipaddr => " + ipaddr)
            logging.debug("src_ipaddr => " + src_ipaddr)
            if ipaddr != src_ipaddr:
                logging.debug("Source => " + src_ipaddr)
                conn_id = str(line[0]).replace(":", "")
                logging.debug("Getting connection ID " + conn_id)
                traffic = get_traffic(host, conn_id)
                connections.append([conn_id, traffic])
                logging.debug("Current [connections,traffic] from " + host + ":9999 " + str(connections))
            else:
                logging.debug("Discarding coordinator connection...")
    return connections


'''
Elimina una sesion pasando ID.
'''


def shudown_session(host, connection):
    logging.info("Shutting down TCP connection...")
    logging.debug("Shutting down TCP connection =>" + host + ":9999:" + connection)
    sendto_socket(host, "shutdown session " + connection)
    return True


'''
Establece el estado de un worker ( via HAPROXY )
'''


def set_server_state(host, state):
    if state == "ready" or state == "drain" or state == "maint":
        logging.info("Setting server state...")
        logging.debug("Setting server => " + host + "state => " + state)
        sendto_socket(host, "set server l1/srv1 state " + state)
    else:
        logging.error("State no supported. Exiting...")

'''
Balanceo teniendo en cuenta la cantidad de sesiones TCP ( agentes ) / Workers"
'''


def tcp_sessions(dryrun=False):
    logging.info("Starting balancing Wazuh Agents via TCP")
    logging.info("dryrun: " + str(dryrun))
    worker_with_conn = []
    total_connections = 0
    total_workers = 0

    workers = get_workers_wazuh_api()
    w_from_k8s = len(get_workers_k8s_api())
    w_from_wazuh = len(workers)

    logging.info("Matching inventory from Wazuh and K8's API...")
    retry = 0
    while w_from_k8s != w_from_wazuh:
        logging.warning('Workers does not match, retrying...')
        sleep(5)
        retry = retry + 1
        workers = get_workers_wazuh_api()
        w_from_k8s = len(get_workers_k8s_api())
        w_from_wazuh = len(workers)
        if retry > 5:
            logging.error('Workers does not match, exiting...')
            exit(1)

    for worker in workers:
        connections = []
        logging.info("Counting agents on Worker " + worker)
        connections_with_load = get_connections(worker)
        for connection_with_load in connections_with_load:
            connection = connection_with_load[0]
            connections.append(connection)
        worker_with_conn.append([worker, connections])
        total_connections = total_connections + len(connections)
        total_workers = total_workers + 1

    fixed_workers_conn = round(total_connections / total_workers)
    logging.info("Total Connections: " + str(total_connections))
    logging.info("Total Workers: " + str(total_workers))
    logging.info("Calculating Fixed connections based on total connections divide into total workers...")
    logging.info("Fixed connections per worker: " + str(fixed_workers_conn))
    # Minimum connections
    if fixed_workers_conn < 1:
        logging.error('Skipping "no_min_conn"')
        return False

    wait = False
    for worker in worker_with_conn:
        connections = worker[1]
        worker = worker[0]
        worker_connections = len(connections)
        logging.debug("Worker => " + worker + " has " + str(worker_connections) + " sessions")
        logging.info("Analyzing if is needed shutdown sessions...")
        if worker_connections > fixed_workers_conn + 1:
            logging.info("Go to shutdown sessions...")
            wait = True
            conn2kill = worker_connections - fixed_workers_conn
            logging.debug("Sessions to kill => " + str(conn2kill))
            i = 0
            logging.debug("Set HAP in DRAIN mode => " + worker)
            if dryrun:
                wait = False
                logging.debug("Set worker " + worker + "in to drain mode")
                # set_server_state(worker, "drain")
                for conn in connections:
                    if conn2kill != i:
                        logging.debug("Shutting down connection =>" + worker + ":" + conn)
                        # shudown_session(worker, conn)
                        i = i + 1
            else:
                logging.debug("Set worker " + worker + "in to drain mode")
                set_server_state(worker, "drain")
                for conn in connections:
                    if conn2kill != i:
                        logging.debug("Shutting down connection =>" + worker + ":" + conn)
                        shudown_session(worker, conn)
                        i = i + 1
        else:
            logging.info("Isn't needed shutdown sessions in Worker " + worker)

    if wait:
        logging.info("Waiting 60s to renew connections...")
        sleep(60)
        for worker in worker_with_conn:
            worker = worker[0]
            set_server_state(worker, "ready")
    else:
        logging.info("Nothing to do, bye...")


if __name__ == "__main__":
    # tcp_sessions()
    args = parse_args()
    set_logger(args.verbosity_level)
    tcp_sessions(dryrun=args.dryrun)
