#import base64
import json
import logging
#import socket
import time
import websocket
import requests
import sys
import re

from . import crypto
from . import exceptions


class RemotePin():
    """Object for remote control connection."""

    def __init__(self, config):
        from . import aes_cipher

        if not config["port"]:
            config["port"] = 8000

        if config["timeout"] == 0:
            config["timeout"] = None

        self.pairing_port = 8080
        self.connection = None
        self.lastRequestId=0
        self.UserId = "654321"
        self.appId = "12345"
        self.deviceId =  "7e509404-9d7c-46b4-8f6a-e2a9668ad184"
        self.HTTP_URL_FORMAT = 'http://{}:{}/socket.io/1/?t={}'
        self.WS_URL_FORMAT = 'ws://{}:{}/socket.io/1/websocket/{}'
        self.config = config
        if config["session_key"] and config["session_id"]:
            self.aesCipher = aes_cipher.AESCipher(config['session_key'], config['session_id'])
        else:
            self.aesCipher = None

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()
    
    def close(self):
        """Close the connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            logging.debug("Connection closed.")

    def control(self, key):
        """Send a control command."""
        """Make a new connection."""
        millis = int(round(time.time() * 1000))
        websocket_key = requests.get(self.HTTP_URL_FORMAT.format(self.config["host"], self.config["port"], millis))
        self.connection = websocket.create_connection(self.WS_URL_FORMAT.format(self.config["host"], self.config["port"], websocket_key.text.split(':')[0]), self.config["timeout"])
        #time.sleep(0.35)
        self.connection.send('1::/com.samsung.companion')
        time.sleep(0.35)
        if not self.aesCipher:
            logging.error("Error: Session key or id is absent")
            raise exceptions.SessionIdKeyAbsent()
        payload = self.aesCipher.generate_command(key)
        logging.info("Sending control command: %s", key)
        self.connection.send(payload)
        #self._read_response()
        #time.sleep(0.35)
        self.connection.close()
        #time.sleep(0.35)
        #time.sleep(self._key_interval)

    _key_interval = 1.0

    def _read_response(self):
        response = self.connection.recv()
        response = json.loads(response)

        if response["event"] != "ms.channel.connect":
            self.close()
            raise exceptions.UnhandledResponse(response)

        logging.debug("Access granted.")

    def pair(self):
        self.lastRequestId = 0
        def getFullUrl(urlPath):
            return "http://{0}:{1}{2}".format(self.config["host"],self.pairing_port,urlPath)

        def GetFullRequestUri(step):
            return getFullUrl("/ws/pairing?step="+str(step)+"&app_id="+self.appId+"&device_id="+self.deviceId)

        def ShowPinPageOnTv():
            requests.post(getFullUrl("/ws/apps/CloudPINPage"), "pin4")

        def CheckPinPageOnTv():
            full_url = getFullUrl("/ws/apps/CloudPINPage")
            page = requests.get(full_url).text
            output = re.search('state>([^<>]*)</state>', page, flags=re.IGNORECASE)
            if output is not None:
                state = output.group(1)
                print("Current state: "+state)
                if state == "stopped":
                    return True
            return False

        def FirstStepOfPairing():
            firstStepURL = GetFullRequestUri(0)+"&type=1"
            firstStepResponse = requests.get(firstStepURL).text

        def StartPairing():
            self.lastRequestId=0
            if CheckPinPageOnTv():
                print("Pin NOT on TV")
                ShowPinPageOnTv()
            else:
                print("Pin ON TV");

        def HelloExchange(pin):
            hello_output = crypto.generateServerHello(self.UserId,pin)
            if not hello_output:
                return False
            content = "{\"auth_Data\":{\"auth_type\":\"SPC\",\"GeneratorServerHello\":\"" + hello_output['serverHello'].hex().upper() + "\"}}"
            secondStepURL = GetFullRequestUri(1)
            secondStepResponse = requests.post(secondStepURL, content).text
            print('secondStepResponse: ' + secondStepResponse)
            output = re.search('request_id.*?(\d).*?GeneratorClientHello.*?:.*?(\d[0-9a-zA-Z]*)', secondStepResponse, flags=re.IGNORECASE)
            if output is None:
                return False
            requestId = output.group(1)
            clientHello = output.group(2)
            self.lastRequestId = int(requestId)
            return crypto.parseClientHello(clientHello, hello_output['hash'], hello_output['AES_key'], self.UserId)

        def AcknowledgeExchange(SKPrime):
            serverAckMessage = crypto.generateServerAcknowledge(SKPrime)
            content="{\"auth_Data\":{\"auth_type\":\"SPC\",\"request_id\":\"" + str(self.lastRequestId) + "\",\"ServerAckMsg\":\"" + serverAckMessage + "\"}}"
            thirdStepURL = GetFullRequestUri(2)
            thirdStepResponse = requests.post(thirdStepURL, content).text
            if "secure-mode" in thirdStepResponse:
                print("TODO: Implement handling of encryption flag!!!!")
                sys.exit(-1)
            output = re.search('ClientAckMsg.*?:.*?(\d[0-9a-zA-Z]*).*?session_id.*?(\d)', thirdStepResponse, flags=re.IGNORECASE)
            if output is None:
                print("Unable to get session_id and/or ClientAckMsg!!!");
                sys.exit(-1)
            clientAck = output.group(1)
            if not crypto.parseClientAcknowledge(clientAck, SKPrime):
                print("Parse client ac message failed.")
                sys.exit(-1)
            sessionId=output.group(2)
            print("sessionId: "+sessionId)
            return sessionId

        def ClosePinPageOnTv():
            full_url = getFullUrl("/ws/apps/CloudPINPage/run");
            requests.delete(full_url)
            return False

        StartPairing()
        ctx = False
        SKPrime = False
        while not ctx:
            tvPIN = input("Please enter pin from tv: ")
            print("Got pin: '"+tvPIN+"'\n")
            FirstStepOfPairing()
            output = HelloExchange(tvPIN)
            if output:
                ctx = output['ctx'].hex()
                SKPrime = output['SKPrime']
                print("ctx: " + ctx)
                print("Pin accepted :)\n")
            else:
                print("Pin incorrect. Please try again...\n")

        currentSessionId = AcknowledgeExchange(SKPrime)
        print("SessionID: " + str(currentSessionId))

        ClosePinPageOnTv()
        print("Authorization successfull :)\n")
