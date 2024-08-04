import requests
import json
import sys
import time
import re
import socket
import datetime
from apscheduler.schedulers.blocking import BlockingScheduler
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#------*****------#

misp_auth_key = "YOUR_MISP_AUTH_KEY"
wazuh_auth_key = "YOUR_WAZUH_AUTH_KEY"
wazuh_group = "YOUR_WAZUH_GROUP"
misp_server = "IP Address of MISP Server"
wazuh_server = "IP Address of Wazuh Server"
frequency = 60 # In minutes

#------*****------#

misp_url = "https://" + misp_server + "/attributes/restSearch/json/null/"
wazuh_post_url = "https://" + wazuh_server + "/api/v4/groups/" + wazuh_group + "/files"

MISP_headers = {
    'authorization': misp_auth_key,
    'cache-control': "no-cache",
    }

Wazuh_headers = {
    'Authorization': 'Bearer ' + wazuh_auth_key,
    'Content-Type': "application/json",
    }

def get_misp_data():
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, GET data from MISP on " + misp_server)
    misp_response = requests.request('GET', misp_url, headers=MISP_headers, verify=False)
    json_data = misp_response.json()
    ioc_list = []
    if misp_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Success) ")
        for data in json_data["response"]["Attribute"]:
            iocs = (data['value'])
            ioc_list.append(iocs)
        import_data = json.dumps(ioc_list)
        ioc_count = len(ioc_list)
        print(time.strftime("%H:%M:%S") + " -- " + str(ioc_count) + " IOCs imported")
        post_to_wazuh(import_data, ioc_count)
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "MISP API Query (Failed), Please check the network connectivity")
        sys.exit()

def post_to_wazuh(import_data, ioc_count):
    print(time.strftime("%H:%M:%S") + " -- " + "Initiating, IOC POST to Wazuh")
    wazuh_response = requests.request("POST", wazuh_post_url, data=import_data, headers=Wazuh_headers, verify=False)
    if wazuh_response.status_code == 200:
        print(time.strftime("%H:%M:%S") + " -- " + "(Finished) Imported " + str(ioc_count) + " IOCs to Wazuh (Success)" )
        print(time.strftime("%H:%M:%S") + " -- " + "Waiting to next schedule in " + str(frequency) + " minutes")
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not POST IOCs to Wazuh (Failure)")

def socket_check_wazuh():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to Wazuh")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((wazuh_server, int(443)))
    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to Wazuh")
        socket_check_misp()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to Wazuh, Please check connectivity before proceeding.")

def socket_check_misp():
    print(time.strftime("%H:%M:%S") + " -- " + "Checking HTTPS Connectivity to MISP")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((misp_server, int(443)))
    if result == 0:
        print(time.strftime("%H:%M:%S") + " -- " + "(Success) HTTPS Connectivity to MISP")
        get_misp_data()
    else:
        print(time.strftime("%H:%M:%S") + " -- " + "Could not establish HTTPS connection to MISP Server, Please check connectivity before proceeding.")

scheduler = BlockingScheduler()
scheduler.add_job(socket_check_wazuh, 'interval', minutes=frequency, next_run_time=datetime.datetime.now())
scheduler.start()
