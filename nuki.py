import time
import nacl.utils
import pygatt.backends
import array
from nacl.public import PrivateKey, Box
from byteswap import ByteSwapper
from crc import CrcCalculator
import nuki_messages
import sys
import configparser
import blescan
import bluetooth._bluetooth as bluez

DEVICE_HANDLEID1 = 'a92ee101-5501-11e4-916c-0800200c9a66'
DEVICE_HANDLEID2 = 'a92ee202-5501-11e4-916c-0800200c9a66'

class Nuki():
    # creates BLE connection with NUKI
    #	-macAddress: bluetooth mac-address of your Nuki Lock
    def __init__(self, macAddress, cfg='/home/nuki/nuki.cfg'):
        self._charWriteResponse = ""
        self.parser = nuki_messages.NukiCommandParser()
        self.crcCalculator = CrcCalculator()
        self.byteSwapper = ByteSwapper()
        self.macAddress = macAddress
        self.config = configparser.RawConfigParser()
        self.config.read(cfg)
        self.device = None

    def _makeBLEConnection(self, retries=3):
        if self.device == None:
            currentTries = 0
            adapter = pygatt.backends.GATTToolBackend()
            nukiBleConnectionReady = False
            while (nukiBleConnectionReady == False and currentTries < retries):
                print("Starting BLE adapter...")
                adapter.start()
                print("Init Nuki BLE connection...")
                try:
                    self.device = adapter.connect(self.macAddress)
                    nukiBleConnectionReady = True
                except:
                    currentTries += 1
                    print("Unable to connect, retrying..., retry count: " + str(currentTries))
        print("Nuki BLE connection established")

    def isNewNukiStateAvailable(self):
        if self.device != None:
            self.device.disconnect()
            self.device = None
        dev_id = 0
        try:
            sock = bluez.hci_open_dev(dev_id)
        except:
            print("error accessing bluetooth device...")
            sys.exit(1)
        blescan.hci_le_set_scan_parameters(sock)
        blescan.hci_enable_le_scan(sock)
        returnedList = blescan.parse_events(sock, 10)
        newStateAvailable = -1
        print("isNewNukiStateAvailable() -> search through %d received beacons..." % len(returnedList))
        for beacon in returnedList:
            beaconElements = beacon.split(',')
            if beaconElements[0] == self.macAddress.lower() and beaconElements[1] == "a92ee200550111e4916c0800200c9a66":
                print("Nuki beacon found, new state element: %s" % beaconElements[4])
                if beaconElements[4] == '-60':
                    newStateAvailable = 0
                else:
                    newStateAvailable = 1
                break
            else:
                print(f"non-Nuki beacon found: mac={beaconElements[0]}, signature={beaconElements[1]}")
        print(f"isNewNukiStateAvailable() -> result={newStateAvailable}")
        return newStateAvailable

    # private method to handle responses coming back from the Nuki Lock over the BLE connection
    def _handleCharWriteResponse(self, handle, value):
        self._charWriteResponse += "".join(format(x, '02x') for x in value)

    # method to authenticate yourself (only needed the very first time) to the Nuki Lock
    #	-publicKeyHex: a public key (as hex string) you created to talk with the Nuki Lock
    #	-privateKeyHex: a private key (complementing the public key, described above) you created to talk with the Nuki Lock
    #	-ID : a unique number to identify yourself to the Nuki Lock
    #	-IDType : '00' for 'app', '01' for 'bridge' and '02' for 'fob'
    #	-name : a unique name to identify yourself to the Nuki Lock (will also appear in the logs of the Nuki Lock)
    def authenticateUser(self, publicKey, privateKeyHex, ID, IDType, name):
        self._makeBLEConnection()
        self.config.remove_section(self.macAddress)
        self.config.add_section(self.macAddress)
        pairingHandle = self.device.get_handle(DEVICE_HANDLEID1)
        print("Nuki Pairing UUID handle created: %04x" % pairingHandle)
        publicKeyReq = nuki_messages.Nuki_REQ(nuki_messages.Nuki_PUBLIC_KEY.command)
        self.device.subscribe(DEVICE_HANDLEID1, self._handleCharWriteResponse, indication=True)
        publicKeyReqCommand = publicKeyReq.generate()
        self._charWriteResponse = ""
        print(f"Requesting Nuki Public Key using command: {publicKeyReq.show()}")
        self.device.char_write_handle(pairingHandle, publicKeyReqCommand, True, 2)
        print("Nuki Public key requested")
        # wtf
        time.sleep(2)
        commandParsed = self.parser.parse(self._charWriteResponse)
        if self.parser.isNukiCommand(self._charWriteResponse) == False:
            sys.exit(f"Error while requesting public key: {commandParsed}")
        if type(commandParsed) != nuki_messages.Nuki_PUBLIC_KEY:
            sys.exit(f"Nuki returned unexpected response (expecting PUBLIC_KEY): {commandParsed.show()}")
        publicKeyNuki = commandParsed.publicKey
        self.config.set(self.macAddress, 'publicKeyNuki', publicKeyNuki)
        self.config.set(self.macAddress, 'publicKeyHex', publicKey.hex())
        self.config.set(self.macAddress, 'privateKeyHex', privateKeyHex)
        self.config.set(self.macAddress, 'ID', ID)
        self.config.set(self.macAddress, 'IDType', IDType)
        self.config.set(self.macAddress, 'Name', name)
        print(f"Public key received: {commandParsed.publicKey}")
        publicKeyPush = nuki_messages.Nuki_PUBLIC_KEY(publicKey)
        publicKeyPushCommand = publicKeyPush.generate()
        print(f"Pushing Public Key using command: {publicKeyPush.show()}")
        self._charWriteResponse = ""
        self.device.char_write_handle(pairingHandle, publicKeyPushCommand, True, 5)
        print("Public key pushed")
        time.sleep(2)
        commandParsed = self.parser.parse(self._charWriteResponse)
        if self.parser.isNukiCommand(self._charWriteResponse) == False:
            sys.exit(f"Error while pushing public key: {commandParsed}")
        if type(commandParsed) != nuki_messages.Nuki_CHALLENGE:
            sys.exit(f"Nuki returned unexpected response (expecting CHALLENGE): {commandParsed.show()}")
        print(f"Challenge received: {commandParsed.nonce}")
        nonceNuki = commandParsed.nonce
        authAuthenticator = nuki_messages.Nuki_AUTH_AUTHENTICATOR()
        authAuthenticator.createPayload(nonceNuki, privateKeyHex, publicKey, publicKeyNuki)
        authAuthenticatorCommand = authAuthenticator.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(pairingHandle, authAuthenticatorCommand, True, 5)
        print(f"Authorization Authenticator sent: {authAuthenticator.show()}")
        time.sleep(2)
        commandParsed = self.parser.parse(self._charWriteResponse)
        if self.parser.isNukiCommand(self._charWriteResponse) == False:
            sys.exit(f"Error while sending Authorization Authenticator: {commandParsed}")
        if type(commandParsed) != nuki_messages.Nuki_CHALLENGE:
            sys.exit(f"Nuki returned unexpected response (expecting CHALLENGE): {commandParsed.show()}")
        print(f"Challenge received: {commandParsed.nonce}")
        nonceNuki = commandParsed.nonce
        authData = nuki_messages.Nuki_AUTH_DATA()
        authData.createPayload(publicKeyNuki, privateKeyHex, nonceNuki, ID, IDType, name)
        authDataCommand = authData.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(pairingHandle, authDataCommand, True, 7)
        print(f"Authorization Data sent: {authData.show()}")
        time.sleep(2)
        commandParsed = self.parser.parse(self._charWriteResponse)
        if self.parser.isNukiCommand(self._charWriteResponse) == False:
            sys.exit(f"Error while sending Authorization Data: {commandParsed}")
        if type(commandParsed) != nuki_messages.Nuki_AUTH_ID:
            sys.exit(f"Nuki returned unexpected response (expecting AUTH_ID): {commandParsed.show()}")
        print(f"Authorization ID received: {commandParsed.show()}")
        nonceNuki = commandParsed.nonce
        authorizationID = commandParsed.authID
        self.config.set(self.macAddress, 'authorizationID', authorizationID)
        authId = int(commandParsed.authID, 16)
        authIDConfirm = nuki_messages.Nuki_AUTH_ID_CONFIRM()
        authIDConfirm.createPayload(publicKeyNuki, privateKeyHex, nonceNuki, authId)
        authIDConfirmCommand = authIDConfirm.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(pairingHandle, authIDConfirmCommand, True, 7)
        print(f"Authorization ID Confirmation sent: {authIDConfirm.show()}")
        time.sleep(2)
        commandParsed = self.parser.parse(self._charWriteResponse)
        if self.parser.isNukiCommand(self._charWriteResponse) == False:
            sys.exit(f"Error while sending Authorization ID Confirmation: {commandParsed}")
        if type(commandParsed) != nuki_messages.Nuki_STATUS:
            sys.exit(f"Nuki returned unexpected response (expecting STATUS): {commandParsed.show()}")
        print(f"STATUS received: {commandParsed.status}")
        with open('/home/nuki/nuki.cfg', 'wb') as configfile:
            self.config.write(configfile)
        return commandParsed.status

    # method to read the current lock state of the Nuki Lock
    def readLockState(self):
        self._makeBLEConnection()
        keyturnerUSDIOHandle = self.device.get_handle(DEVICE_HANDLEID2)
        self.device.subscribe(DEVICE_HANDLEID2, self._handleCharWriteResponse, indication=True)
        stateReq = nuki_messages.Nuki_REQ(nuki_messages.Nuki_STATES.command)
        stateReqEncrypted = nuki_messages.Nuki_EncryptedCommand(
            authID=self.config.get(self.macAddress, 'authorizationID'),
            nukiCommand=stateReq,
            publicKey=self.config.get(self.macAddress, 'publicKeyNuki'),
            privateKey=self.config.get(self.macAddress,
                                       'privateKeyHex'))
        stateReqEncryptedCommand = stateReqEncrypted.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(keyturnerUSDIOHandle, stateReqEncryptedCommand, True, 3)
        print(f"Nuki State Request sent: {stateReq.show()}\nresponse received: {self._charWriteResponse}")
        time.sleep(2)
        commandParsed = self.parser.decrypt(self._charWriteResponse, self.config.get(self.macAddress, 'publicKeyNuki'),
                                            self.config.get(self.macAddress, 'privateKeyHex'))[8:]
        if self.parser.isNukiCommand(commandParsed) == False:
            sys.exit(f"Error while requesting Nuki STATES: {commandParsed}")
        commandParsed = self.parser.parse(commandParsed)
        if type(commandParsed) != nuki_messages.Nuki_STATES:
            sys.exit(f"Nuki returned unexpected response (expecting Nuki STATES): {commandParsed.show()}")
        # wtf
        print("%s" % commandParsed.show())
        return commandParsed

    # method to perform a lock action on the Nuki Lock:
    #	-lockAction: 'UNLOCK', 'LOCK', 'UNLATCH', 'LOCKNGO', 'LOCKNGO_UNLATCH', 'FOB_ACTION_1', 'FOB_ACTION_2' or 'FOB_ACTION_3'
    def lockAction(self, lockAction):
        self._makeBLEConnection()
        keyturnerUSDIOHandle = self.device.get_handle(DEVICE_HANDLEID2)
        self.device.subscribe(DEVICE_HANDLEID2, self._handleCharWriteResponse, indication=True)
        challengeReq = nuki_messages.Nuki_REQ(nuki_messages.Nuki_CHALLENGE.command)
        challengeReqEncrypted = nuki_messages.Nuki_EncryptedCommand(
            authID=self.config.get(self.macAddress, 'authorizationID'), nukiCommand=challengeReq,
            publicKey=self.config.get(self.macAddress, 'publicKeyNuki'),
            privateKey=self.config.get(self.macAddress, 'privateKeyHex'))
        challengeReqEncryptedCommand = challengeReqEncrypted.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(keyturnerUSDIOHandle, challengeReqEncryptedCommand, True, 4)
        print(f"Nuki CHALLENGE Request sent: {challengeReq.show()}")
        time.sleep(2)
        commandParsed = self.parser.decrypt(self._charWriteResponse, self.config.get(self.macAddress, 'publicKeyNuki'),
                                            self.config.get(self.macAddress, 'privateKeyHex'))[8:]
        if self.parser.isNukiCommand(commandParsed) == False:
            sys.exit(f"Error while requesting Nuki CHALLENGE: {commandParsed}")
        commandParsed = self.parser.parse(commandParsed)
        if type(commandParsed) != nuki_messages.Nuki_CHALLENGE:
            sys.exit(f"Nuki returned unexpected response (expecting Nuki CHALLENGE): {commandParsed.show()}")
        print(f"Challenge received: {commandParsed.nonce}")
        lockActionReq = nuki_messages.Nuki_LOCK_ACTION()
        lockActionReq.createPayload(self.config.getint(self.macAddress, 'ID'), lockAction, commandParsed.nonce)
        lockActionReqEncrypted = nuki_messages.Nuki_EncryptedCommand(
            authID=self.config.get(self.macAddress, 'authorizationID'),
            nukiCommand=lockActionReq,
            publicKey=self.config.get(self.macAddress, 'publicKeyNuki'),
            privateKey=self.config.get(self.macAddress, 'privateKeyHex'),
            )
        lockActionReqEncryptedCommand = lockActionReqEncrypted.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(keyturnerUSDIOHandle, lockActionReqEncryptedCommand, True, 4)
        print(f"Nuki Lock Action Request sent: {lockActionReq.show()}")
        time.sleep(2)
        commandParsed = self.parser.decrypt(self._charWriteResponse, self.config.get(self.macAddress, 'publicKeyNuki'),
                                            self.config.get(self.macAddress, 'privateKeyHex'))[8:]
        if self.parser.isNukiCommand(commandParsed) == False:
            sys.exit(f"Error while requesting Nuki Lock Action: {commandParsed}")
        commandParsed = self.parser.parse(commandParsed)
        if type(commandParsed) not in [nuki_messages.Nuki_STATES, nuki_messages.Nuki_STATUS]:
            sys.exit(f"Nuki returned unexpected response (expecting Nuki STATUS/STATES): {commandParsed.show()}")
        # wtf
        print("%s" % commandParsed.show())

    # method to fetch the number of log entries from your Nuki Lock
    #	-pinHex : a 2-byte hex string representation of the PIN code you have set on your Nuki Lock (default is 0000)
    def getLogEntriesCount(self, pinHex):
        self._makeBLEConnection()
        keyturnerUSDIOHandle = self.device.get_handle(DEVICE_HANDLEID2)
        self.device.subscribe(DEVICE_HANDLEID2, self._handleCharWriteResponse, indication=True)
        challengeReq = nuki_messages.Nuki_REQ(nuki_messages.Nuki_CHALLENGE.command)
        challengeReqEncrypted = nuki_messages.Nuki_EncryptedCommand(
            authID=self.config.get(self.macAddress, 'authorizationID'), nukiCommand=challengeReq,
            publicKey=self.config.get(self.macAddress, 'publicKeyNuki'),
            privateKey=self.config.get(self.macAddress, 'privateKeyHex'))
        challengeReqEncryptedCommand = challengeReqEncrypted.generate()
        self._charWriteResponse = ""
        print(f"Requesting CHALLENGE: {challengeReqEncrypted.generate('HEX')}")
        self.device.char_write_handle(keyturnerUSDIOHandle, challengeReqEncryptedCommand, True, 5)
        print("Nuki CHALLENGE Request sent: %s" % challengeReq.show())
        time.sleep(2)
        commandParsed = self.parser.decrypt(self._charWriteResponse, self.config.get(self.macAddress, 'publicKeyNuki'),
                                            self.config.get(self.macAddress, 'privateKeyHex'))[8:]
        if self.parser.isNukiCommand(commandParsed) == False:
            sys.exit(f"Error while requesting Nuki CHALLENGE: {commandParsed}")
        commandParsed = self.parser.parse(commandParsed)
        if type(commandParsed) != nuki_messages.Nuki_CHALLENGE:
            sys.exit(f"Nuki returned unexpected response (expecting Nuki CHALLENGE): {commandParsed.show()}")
        print(f"Challenge received: {commandParsed.nonce}")
        logEntriesReq = nuki_messages.Nuki_LOG_ENTRIES_REQUEST()
        logEntriesReq.createPayload(0, commandParsed.nonce, self.byteSwapper.swap(pinHex))
        logEntriesReqEncrypted = nuki_messages.Nuki_EncryptedCommand(
            authID=self.config.get(self.macAddress, 'authorizationID'),
            nukiCommand=logEntriesReq,
            publicKey=self.config.get(self.macAddress, 'publicKeyNuki'),
            privateKey=self.config.get(self.macAddress, 'privateKeyHex'),
            )
        logEntriesReqEncryptedCommand = logEntriesReqEncrypted.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(keyturnerUSDIOHandle, logEntriesReqEncryptedCommand, True, 4)
        print(f"Nuki Log Entries Request sent: {logEntriesReq.show()}")
        time.sleep(2)
        commandParsed = self.parser.decrypt(self._charWriteResponse, self.config.get(self.macAddress, 'publicKeyNuki'),
                                            self.config.get(self.macAddress, 'privateKeyHex'))[8:]
        if self.parser.isNukiCommand(commandParsed) == False:
            sys.exit(f"Error while requesting Nuki Log Entries: {commandParsed}")
        commandParsed = self.parser.parse(commandParsed)
        if type(commandParsed) != nuki_messages.Nuki_LOG_ENTRY_COUNT:
            sys.exit(f"Nuki returned unexpected response (expecting Nuki LOG ENTRY): {commandParsed.show()}")
        print("%s" % commandParsed.show())
        return int(commandParsed.logCount, 16)

    # method to fetch the most recent log entries from your Nuki Lock
    #	-count: the number of entries you would like to fetch (if available)
    #	-pinHex : a 2-byte hex string representation of the PIN code you have set on your Nuki Lock (default is 0000)
    def getLogEntries(self, count, pinHex):
        self._makeBLEConnection()
        keyturnerUSDIOHandle = self.device.get_handle(DEVICE_HANDLEID2)
        self.device.subscribe(DEVICE_HANDLEID2, self._handleCharWriteResponse, indication=True)
        challengeReq = nuki_messages.Nuki_REQ(nuki_messages.Nuki_CHALLENGE.command)
        challengeReqEncrypted = nuki_messages.Nuki_EncryptedCommand(
            authID=self.config.get(self.macAddress, 'authorizationID'), nukiCommand=challengeReq,
            publicKey=self.config.get(self.macAddress, 'publicKeyNuki'),
            privateKey=self.config.get(self.macAddress, 'privateKeyHex'))
        challengeReqEncryptedCommand = challengeReqEncrypted.generate()
        print(f"Requesting CHALLENGE: {challengeReqEncrypted.generate('HEX')}")
        self._charWriteResponse = ""
        self.device.char_write_handle(keyturnerUSDIOHandle, challengeReqEncryptedCommand, True, 5)
        print("Nuki CHALLENGE Request sent: %s" % challengeReq.show())
        time.sleep(2)
        commandParsed = self.parser.decrypt(self._charWriteResponse, self.config.get(self.macAddress, 'publicKeyNuki'),
                                            self.config.get(self.macAddress, 'privateKeyHex'))[8:]
        if self.parser.isNukiCommand(commandParsed) == False:
            sys.exit("Error while requesting Nuki CHALLENGE: %s" % commandParsed)
        commandParsed = self.parser.parse(commandParsed)
        if type(commandParsed) != nuki_messages.Nuki_CHALLENGE:
            sys.exit("Nuki returned unexpected response (expecting Nuki CHALLENGE): %s" % commandParsed.show())
        print("Challenge received: %s" % commandParsed.nonce)
        logEntriesReq = nuki_messages.Nuki_LOG_ENTRIES_REQUEST()
        logEntriesReq.createPayload(count, commandParsed.nonce, self.byteSwapper.swap(pinHex))
        logEntriesReqEncrypted = nuki_messages.Nuki_EncryptedCommand(
            authID=self.config.get(self.macAddress, 'authorizationID'), nukiCommand=logEntriesReq,
            publicKey=self.config.get(self.macAddress, 'publicKeyNuki'),
            privateKey=self.config.get(self.macAddress, 'privateKeyHex'))
        logEntriesReqEncryptedCommand = logEntriesReqEncrypted.generate()
        self._charWriteResponse = ""
        self.device.char_write_handle(keyturnerUSDIOHandle, logEntriesReqEncryptedCommand, True, 6)
        print("Nuki Log Entries Request sent: %s" % logEntriesReq.show())
        time.sleep(2)
        messages = self.parser.splitEncryptedMessages(self._charWriteResponse)
        print("Received %d messages" % len(messages))
        logMessages = []
        for message in messages:
            print(f"Decrypting message {message}")
            try:
                commandParsed = self.parser.decrypt(message, self.config.get(self.macAddress, 'publicKeyNuki'),
                                                    self.config.get(self.macAddress, 'privateKeyHex'))[8:]
                if self.parser.isNukiCommand(commandParsed) == False:
                    sys.exit(f"Error while requesting Nuki Log Entries: {commandParsed}")
                commandParsed = self.parser.parse(commandParsed)
                if type(commandParsed) not in [nuki_messages.Nuki_LOG_ENTRY, nuki_messages.Nuki_LOG_ENTRY_COUNT, nuki_messages.Nuki_STATUS]:
                    sys.exit("Nuki returned unexpected response (expecting Nuki LOG ENTRY): %s" % commandParsed.show())
                print("%s" % commandParsed.show())
                if type(commandParsed) == nuki_messages.Nuki_LOG_ENTRY:
                    logMessages.append(commandParsed)
            except:
                print("Unable to decrypt message")
        return logMessages
