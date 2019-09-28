import requests
import threading
import logging
import time
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, REGISTRY
import configparser
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class CustomCollector(object):
    def __init__(self):
        super().__init__()
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.port = int(config['SVT']['PORT'])
        logging.info("Starting svtexporter on port: %d", self.port)
        self.username = config['SVT']['USERNAME']
        self.password = config['SVT']['PASSWORD']
        self.svthost = config['SVT']['HOST']
        self.session_time = 0
        self.s = requests.Session()
        self.bearer_token = self.refresh_api_token()

    def refresh_api_token(self):
        valid_session = False
        while valid_session is False:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = [
                ('username', self.username),
                ('password', self.password),
                ('grant_type', 'password'),
            ]
            try:
                # SimpliVity API requires basic-auth for with 'simplivity' and a blank password to this endpoint
                # even though credentials are submitted in the POST data portion
                r = self.s.post('https://{}/api/oauth/token'.format(self.svthost),
                                headers=headers, data=data, verify=False, auth=('simplivity', ''))
                r.raise_for_status()  # This will cause exceptions for non-200 responses
                valid_session = True
            except Exception as inst:
                logging.error('Error refreshing API token: %s, %s', inst, r.content)
                time.sleep(5)

        self.session_time = time.time()
        json_data = r.json()
        logging.info('Refreshed API token: %s', json_data)
        return json_data

    def make_request(self, url, query_data):
        # Check to see if our session has timed out yet or not
        if int(time.time()) > int(self.session_time + self.bearer_token['expires_in'] + 5):
            self.bearer_token = self.refresh_api_token()
        headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer {}'.format(self.bearer_token['access_token']),
            'Access-Control-Allow-Origin': '*'
        }
        try:
            if query_data is not None:
                r = self.s.get('https://{}/api'.format(self.svthost) + url, headers=headers, verify=False, params=query_data)
            else:
                r = self.s.get('https://{}/api'.format(self.svthost) + url, headers=headers, verify=False)

            if not r:
                logging.info('Request returned {} for {}: {}'.format(r.status_code, r.url, r.reason))

            return json.loads(r.text)

        except Exception as inst:
            logging.error('Error making API request: %s', inst)
            return None

    def collect(self):
        try:
            start = time.time()
            svt_hosts = self.make_request('/hosts', None)
            elapsed = time.time() - start
            logging.debug("Retrieving host list took %s", elapsed)
        except Exception as inst:
            logging.error('Error getting stats: %s', inst)

        try:
            start = time.time()
            for host in svt_hosts['hosts']:
                data = {
                   'fields': 'used_capacity,allocated_capacity,free_space',
                   'time_offset': 60,
                   'range': 60,
                   'resolution': 'SECOND'
                }
                svt_storage = self.make_request('/hosts/{}/capacity'.format(host['id']), data)
                if not svt_storage['metrics']:
                    logging.error('Error getting metrics for {}'.format(host['name']))
                for metric in svt_storage['metrics']:
                    if metric['data_points']:
                        sgm = GaugeMetricFamily(metric['name'], 'SimpliVity {}'.format(metric['name']),
                                                labels=['server', 'svt_cluster'])
                        sgm.add_metric([host['name'], host['compute_cluster_name']], value=metric['data_points'][0]['value'])
                        yield sgm
                    else:
                        logging.debug('No data points for metric {} on host {}'.format(metric, host['name']))
            elapsed = time.time() - start
            logging.debug("Retrieving capacity for all hosts took %s", elapsed)
        except Exception as inst:
            logging.error('Error getting storage info for all hosts: %s', inst)


if __name__ == '__main__':
    # Set up logging, so that logs go to STDERR and also to a file
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s",
        datefmt='%Y/%m/%d %H:%M:%S',
        handlers=[
            logging.FileHandler("svtexporter.log"),
            logging.StreamHandler()
        ])

    svtexporter = CustomCollector()
    REGISTRY.register(svtexporter)
    start_http_server(svtexporter.port)
    DE = threading.Event()
    DE.wait()