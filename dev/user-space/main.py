import nsocket
import json
import time
import datetime
import logging

NETLINK_USER = 17

### Import config.json

config_file = open('./config/config.json')
config = json.load(config_file)

### Import rules.json

rules_file = open(config["rulesFile"])
rules_list = json.load(rules_file)

### Create message for "protectFiles" to send to kernel module

rules_message = ""

for rules in rules_list["protectFiles"]:
    rules_message += "priority=" + rules["priority"] + ";"
    rules_message += "importantFiles="

    i = 0
    for file in rules["importantFiles"]:
        if (i == len(rules["importantFiles"]) - 1):
            rules_message += file
            break
        rules_message += file + ","

        i += 1

    rules_message += "&"

### Send the message to the kernel module
try:
    netlink_socket = nsocket.NetlinkSocket(NETLINK_USER)
    netlink_socket.sendto(rules_message)
except:
    print('Error while creating netlink socket')

### Log received messages to file from config
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.FileHandler(config["logFile"], 'a', 'utf-8')
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(handler)

try:
    print('Writing logs to file ' + config["logFile"])
    while(1):
        try:
            # Receive message from kernel module
            received_message = netlink_socket.recvfrom(8192 * 4)

            # Log the message
            logger.info(received_message)
        except Exception as err:
            print(err)
except KeyboardInterrupt:
    print('Closing netlink socket')
    netlink_socket.close()
