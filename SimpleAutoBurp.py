from os import strerror
from subprocess import Popen
import requests
import time
import subprocess
import logging
import os
import signal
import json
import sys
from datetime import datetime

configFile = sys.argv[1] if len(sys.argv)==2 else "config.json"

try:
    with open(configFile) as json_data:
        config=json.load(json_data)
except:
    print("Missing config.json file. Make sure the configuration file is in the same folder")
    exit()

burpConfigs=config["burpConfigs"][0]
siteConfigs=config["sites"]

def set_logging():
    global rootLogger
    logFormatter = logging.Formatter("%(asctime)s [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()
    NumericLevel = getattr(logging, burpConfigs["loglevel"].upper(), 10)
    rootLogger.setLevel(NumericLevel)

    fileHandler = logging.FileHandler("{0}/{1}.log".format(burpConfigs["logPath"], burpConfigs["logfileName"]))
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)

def execute_burp(site):
    cmd = burpConfigs["java"] + " -jar -Xmx" + burpConfigs["memory"] + " -Djava.awt.headless=" \
        + str(burpConfigs["headless"]) + " " + burpConfigs["burpJar"] + " --project-file=" + site["project"] + " --unpause-spider-and-scanner"
    try:
        rootLogger.debug("Executing Burp: " + str(cmd))
        p = Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return p.pid
    except:
        rootLogger.error("Burp Suite failed to execute.")
        exit()

def check_burp(site):
    count = 0
    url = "http://127.0.0.1:1337/"+ site["apikey"] +"/v0.1/"
    time.sleep(10)
    while True:
        if count > burpConfigs["retry"]:
            rootLogger.error("Too many attempts to connect to Burp")
            exit()
        else:
            rootLogger.debug("Cheking API: " + str(url))
            init = requests.get(url)
            if init.status_code == 200:
                rootLogger.debug("API running, response code: " + str(init.status_code))
                # Let Brup time to load extensions
                time.sleep(30)
                break
            else:
                rootLogger.debug("Burp is not ready yet, response code: " + str(init.status_code))
                time.sleep(10)

def execute_scan(site):
    data = '{"urls":["'+ site["scanURL"] + '"]}'
    url="http://127.0.0.1:1337/" + site["apikey"] + "/v0.1/scan"
    rootLogger.info("Starting scan to: " + str(site["scanURL"]))
    scan = requests.post(url, data=data)
    rootLogger.debug("Task ID: " + scan.headers["Location"])
    while True:
        url="http://127.0.0.1:1337/" + site["apikey"] + "/v0.1/scan/" + scan.headers["Location"]
        scanresults = requests.get(url)
        data = scanresults.json()
        rootLogger.info("Current status: " + data["scan_status"])
        if data["scan_status"] == "failed":
            rootLogger.error("Scan failed")
            kill_burp()
            exit()
        elif data["scan_status"] == "succeeded":
            rootLogger.info("Scan competed")
            return data
        else:
            rootLogger.debug("Waiting 60 before cheking the status again")
            time.sleep(60)

def kill_burp(child_pid):
    rootLogger.info("Killing Burp.")
    try:
            os.kill(child_pid, signal.SIGTERM)
            rootLogger.debug("Burp killed")
    except:
            rootLogger.error("Failed to stop Burp")

def get_data(data, site):
    for issue in data["issue_events"]:
        rootLogger.info("Vulnerability - Name: " + issue["issue"]["name"] + " Path: " + issue["issue"]["path"] + " Severity: " + issue["issue"]["severity"])
    token=site["scanURL"].split('/')[2]
    top_level=token.split('.')[-2]+'.'+token.split('.')[-1]
    file = top_level + "-" + datetime.now().strftime("%Y_%m_%d-%I_%M_%S_%p") + ".txt"
    file = burpConfigs["ScanOutput"] + file
    rootLogger.info("Writing full results to: "+ file)
    with open(file, "w") as f:
        f.write(str(data["issue_events"]))

def main():
    set_logging()
    for site in config["sites"]:
        # Execute BurpSuite Pro
        child_pid = execute_burp(site)
        # Check if API burp is up
        check_burp(site)
        # Execute Scan
        data = execute_scan(site)
        # Get Vulnerability data
        get_data(data, site)
        # Stop Burp
        rootLogger.info("Scan finished, killing Burp.")
        kill_burp(child_pid)

if __name__ == '__main__':
    main() 
