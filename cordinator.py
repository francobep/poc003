#!/usr/bin/env python3

import logging
import re
import socket
import requests
import six
import argparse
import itertools
from time import sleep
from kubernetes import client, config


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lbmode",
                        action="store",
                        type=int,
                        help="1 => TCP Sessions, 2 => TCP Sessions with Network Load. Default=1",
                        default=1,
                        dest="lbmode")
    parser.add_argument("--v",
                        "-v",
                        action="store",
                        type=int,
                        help="1 => INFO, 2 => Warning, 3 => DEBUG. Default=1",
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
    """
    Set logging
    :param verbosity_level: int between 1,2,3
    """
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


def sendto_socket(host, msg):
    """
    Send encoded strings to HAPROXY API Runtime SOCKET
    :param host: string IP of Worker
    :param msg: string Message to sent
    :return data: string Message from SOCKET
    """
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


def get_workers_k8s_api():
    """
    Get workers nodes from "endpoints" in a service via K8's API.
    :return workers: list List of workers IP
    """
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


def get_workers_wazuh_api():
    """
    Get workers nodes from Wazuh Manager API.
    :return workers: list List of workers IP
    """
    logging.info("Getting workers from Wazuh API")
    namespace = 'wazuh'  # TODO:Get NAMESPACE POD
    base_url = 'https://wazuh-manager-master-0.wazuh-cluster.' + namespace + '.svc.cluster.local:55000'
    auth = requests.auth.HTTPBasicAuth('foo', 'bar')  # TODO Get API Credentials
    requests.packages.urllib3.disable_warnings()
    workers = []
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


def get_traffic(host, conn):
    """
    Get connection's traffic via HAPROXY
    :param host: string IP of worker
    :param conn: string ID HEX of Connection
    :return traffic: int Sum of Traffic
    """
    traffic = 0
    logging.debug("Getting connection traffic " + host + ":9999:" + conn)
    rdata = sendto_socket(host, "show sess " + conn)
    rawtotals = re.findall(r"(total=\d+)", str(rdata))

    for total in rawtotals:

        if traffic == 0:
            logging.debug("Connection " + host + ":9999:" + conn + " bytes inbound " + str(total))
        else:
            logging.debug("Connection " + host + ":9999:" + conn + " bytes outbound " + str(total))

        tbytes = int(total.replace("total=", ""))
        traffic = traffic + tbytes
    return traffic


def get_connections(host):
    """
    Get connections of a Worker via HAPROXY
    :param host: string IP of worker
    :return connections: list List of connections
    """
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


def shutdown_session(host, conn):
    """
    Shutdown a specific connection via HAPROXY
    :param host: string IP of worker
    :param conn: string ID HEX of Connection
    """
    logging.info("Shutting down TCP connection...")
    logging.debug("Shutting down TCP connection =>" + host + ":9999:" + conn)
    sendto_socket(host, "shutdown session " + conn)


def set_server_state(host, state):
    """
    Set state to a Worker via HAPROXY
    :param host: string IP of worker
    :param state: string States of server. (ready,drain,maint)
    """
    if state == "ready" or state == "drain" or state == "maint":
        logging.info("Setting server state...")
        logging.debug("Setting server => " + host + " state => " + state)
        sendto_socket(host, "set server l1/srv1 state " + state)
    else:
        logging.error("State no supported. Exiting...")


def get_workers_with_traffic(workers):
    """
    Set state to a Worker via HAPROXY
    :param workers: List of Worker's IP
    :return workers_with_conn: list List of tuples [workers,[[connection,traffic]]]
    :return total_connections: int Sum of all connections
    :return total_traffic: int Sum of all traffic
    """
    workers_with_conn = []
    total_connections = 0
    total_traffic = 0

    for worker in workers:
        connections = []
        connections_with_traffic = get_connections(worker)

        for connection_with_traffic in connections_with_traffic:
            connection = connection_with_traffic[0]
            connection_traffic = connection_with_traffic[1]
            total_traffic = total_traffic + connection_traffic
            connections.append([connection, connection_traffic])

        workers_with_conn.append([worker, connections])
        total_connections = total_connections + len(connections)

    return workers_with_conn, total_connections, total_traffic


def get_stats(workers):
    """
    Set state to a Worker via HAPROXY
    :param workers: List of Worker's IP
    """
    logging.info("Workers Statistics")
    workers_with_conn = get_workers_with_traffic(workers)

    for worker_with_con in workers_with_conn:
        for worker in worker_with_con:
            logging.info("Worker => " + worker[0] + " has " + str(len(worker[1])) + " connections")


def get_fixed_workers_traffic(traffic, workers):
    """
    Divide traffic into workers
    :param traffic: int Sum of traffic from all connections
    :param workers: list List of Worker's IP
    """
    fixed_workers_traffic = round(traffic / workers)
    return fixed_workers_traffic


def tcp_sessions(sleeptime=3, lbmode=1, dryrun=False):
    """
    Divide traffic into workers
    :param sleeptime: int Seconds to sleep between A/B moments
    :param lbmode: int Type of load balance mode.
    :param dryrun: bool

    """
    logging.info("Starting balancing Wazuh Agents lbmode => " + str(lbmode))
    logging.info("dryrun: " + str(dryrun))
    workers = get_workers_wazuh_api()
    #Get Initial State
    get_stats(workers)
    total_workers = len(workers)
    w_from_k8s = len(get_workers_k8s_api())
    w_from_wazuh = len(workers)
    wait = not dryrun
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

    if lbmode == 1:
        workers_with_conn, total_connections, total_traffic = get_workers_with_traffic(workers)
        fixed_workers_conn = round(total_connections / total_workers)
        logging.info("################################################")
        logging.info("################################################")
        logging.info("Total Connections: " + str(total_connections))
        logging.info("Total Workers: " + str(total_workers))
        logging.info("Calculating Fixed connections based on total connections divide into total workers...")
        logging.info("Fixed connections per worker: " + str(fixed_workers_conn))
        logging.info("################################################")
        logging.info("################################################")

        if fixed_workers_conn < 1:
            logging.error('Skipping "no_min_conn"')
            return False

        for worker in workers_with_conn:
            connections = worker[1]
            worker = worker[0]
            worker_connections = len(connections)
            logging.info("Analyzing if is needed shutdown sessions in worker " + worker + "...")
            logging.debug("Worker => " + worker + " has " + str(worker_connections) + " sessions")

            if worker_connections > fixed_workers_conn + 1:
                logging.info("Go to shutdown sessions...")
                conn2kill = worker_connections - fixed_workers_conn
                logging.debug("Sessions to kill => " + str(conn2kill))
                i = 0
                logging.debug("Set HAP in DRAIN mode => " + worker)
                logging.debug("Set worker " + worker + "in to drain mode")
                set_server_state(worker, "drain")

                for conn in connections:
                    if conn2kill != i:
                        logging.debug("Shutting down connection =>" + worker + ":" + conn[0])
                        if not dryrun:
                            shutdown_session(worker, conn[0])
                            i = i + 1
            else:
                logging.info("Isn't needed shutdown sessions in Worker " + worker)
    else:
        # Moment A
        workers_with_conn_a, total_connections_a, total_traffic_a = get_workers_with_traffic(workers)
        logging.info("Sleeping " + str(sleeptime) + " seconds to take a traffic metric")
        sleep(sleeptime)
        # Moment B
        workers_with_conn, total_connections, total_traffic = get_workers_with_traffic(workers)

        for (a, b) in itertools.zip_longest(workers_with_conn_a, workers_with_conn):
            for (c, d) in itertools.zip_longest(a[1], b[1]):
                try:
                    traffic = d[1] - c[1]
                except requests.exceptions as e:
                    logging.error(e)
                    return False
                else:
                    d[1] = traffic

        total_traffic = total_traffic - total_traffic_a
        logging.info("################################################")
        logging.info("################################################")
        logging.info("Total Connections: " + str(total_connections))
        logging.info("Total Traffic: " + str(total_traffic))
        logging.info("Total Workers: " + str(total_workers))
        logging.info("Calculating Fixed connections based on total traffic connections divide into total workers...")
        logging.info("################################################")
        logging.info("################################################")

        for worker in workers_with_conn:
            fixed_workers_traffic = get_fixed_workers_traffic(total_traffic, total_workers)
            logging.info("Fixed traffic per worker: " + str(fixed_workers_traffic))
            connections = worker[1]
            worker = worker[0]
            worker_traffic = 0
            logging.info("Analyzing if is needed shutdown sessions in worker " + worker + "...")

            for conn in connections:
                conn_traffic = conn[1]
                worker_traffic = worker_traffic + conn_traffic
                logging.debug("Connection Traffic => " + str(conn_traffic))
                logging.debug("Calculating Worker traffic => " + str(worker_traffic))

                if worker_traffic > fixed_workers_traffic:
                    logging.info("Worker " + worker + " has " + str(worker_traffic) + " traffic. Is over the limit!")
                    logging.info("Go to shutdown sessions...")
                    logging.debug("Set HAP in DRAIN mode => " + worker)
                    logging.debug("Set worker " + worker + " in to drain mode")
                    set_server_state(worker, "drain")
                    logging.debug("Shutting down connection => " + worker + ":" + conn[0])

                    if not dryrun:
                        shutdown_session(worker, conn[0])

            logging.info("Go to next worker...")

            if total_workers > 2:
                logging.debug("Rest worker traffic to total traffic")
                total_traffic = total_traffic - worker_traffic
                logging.debug("Rest of traffic => " + str(total_traffic))
                total_workers = total_workers - 1
                logging.debug("Rest of Workers => " + str(total_workers))
            else:
                logging.debug("Need at least 2 workers, don't recalculate fixed traffic, skipping...")

    if wait:
        logging.info("Waiting 10s to renew connections...")
        sleep(10)
        for worker in workers:
            worker = worker
            set_server_state(worker, "ready")
    else:
        logging.info("Nothing to do, bye...")
    #Get Final State
    get_stats(workers)

def main():
    args = parse_args()
    set_logger(args.verbosity_level)
    tcp_sessions(lbmode=args.lbmode, dryrun=args.dryrun)


if __name__ == "__main__":
    args = parse_args()
    set_logger(args.verbosity_level)
    workers = get_workers_wazuh_api()
    get_stats(workers)


    main()
