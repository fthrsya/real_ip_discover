#usage python3 random.py example.com "<title>example" -t256

import logging
import os
import sys
from argparse import SUPPRESS, ArgumentParser
import requests
import urllib3
from netaddr import *
import _thread
import itertools
import math
import random

try:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError as ie:
    print(ie)

LOGGING_FORMAT = "%(asctime)s: %(message)s"
PROTOCOLS = ("http", "https")
range_length = 0
total_requests = 0
sent_requests = 0
matches = 0

def generate_random_ipv4():
    ip_parts = [str(random.randint(0, 255)) for _ in range(4)]
    ip_address = ".".join(ip_parts)
    return ip_address

def send_request(i, args):
    global sent_requests, matches
    
    while True:
        ipaddr=generate_random_ipv4();

        targethttp = f"http://{ipaddr}{args.uri}"
        targethttps = f"https://{ipaddr}{args.uri}"

        logging.debug(f"Trying {targethttps}...")

        #gor_https
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0",
                "Host": args.hostname,
            }
            response = requests.get(
                targethttps, headers=headers, verify=False, timeout=args.timeout, allow_redirects=False
            )
            if str(args.match) in str(response.content):
                matches = matches + 1
                resp_size = str(round(len(response.content) / 1024))
                msg = f"\033[92m request to {ipaddr} matchs ({resp_size}kb)\033[0m \n \
                    check it: \"curl -H 'Host: {args.hostname}' {targethttps} -k\""
                logging.info(f"{msg}")

        except:
            logging.debug(f"{targethttps} not responds")

        #for_http
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:66.0) Gecko/20100101 Firefox/66.0",
                "Host": args.hostname,
            }
            response = requests.get(
                targethttp, headers=headers, verify=False, timeout=args.timeout, allow_redirects=False
            )
            if str(args.match) in str(response.content):
                matches = matches + 1
                resp_size = str(round(len(response.content) / 1024))
                msg = f"\033[92m request to {ipaddr} matchs ({resp_size}kb)\033[0m \n \
                    check it: \"curl -H 'Host: {args.hostname}' {targethttp} -k\""
                logging.info(f"{msg}")

        except:
            logging.debug(f"{targethttp} not responds")



def main(args):
    global range_length, total_requests

    try:
        # start threads
        for i in range(args.threads):
            _thread.start_new_thread(send_request, (i,args))

    except Exception as e:
        logging.warning(f"Error: unable to start thread. {e}")

    while True:
        pass

if __name__ == "__main__":
    parser = ArgumentParser(
        add_help=True,
        description="This tool helps you to find a website server ip in an ipv4 range or list.",
        usage=SUPPRESS,
    )
    parser.add_argument("hostname", help="Ex: site.com")
    parser.add_argument("match", help='Ex: "welcome to site.com"')
    parser.add_argument("-u", "--uri", help="Ex: /en/index.aspx", default="/")
    parser.add_argument("-t", "--threads", help="", type=int, default=10)
    parser.add_argument("-T", "--timeout", help="", type=int, default=3)
    parser.add_argument(
        "-v", "--verbose", help="Verbose mode", dest="verbose", action="store_true"
    )

    args = parser.parse_args()

    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format=LOGGING_FORMAT, datefmt='%H:%M:%S')

    try:
        main(args)
    except KeyboardInterrupt:
        print("\nStopped")
        sys.exit()
    
