from flask import Flask 
from configparser import SafeConfigParser 
import nuki 
from nacl.public import PrivateKey 
from flask import jsonify

parser = SafeConfigParser()
parser.read('nuki.cfg')

app = Flask(__name__)

def parse_config():
    config_dict = {}
    for sect in parser.sections():
        for name, value in parser.items(sect):
            if name == "name":
                config_dict[value] = sect
    return config_dict

config = parse_config()
print(config)

@app.route("/")
def get_config():
    return config

@app.route("/connect/<mac_address>/<name>")
def connect(mac_address, name):
    # generate the private key which must be kept secret
    keypair = PrivateKey.generate()
    myID = 50
    # id-type = 00 (app), 01 (bridge) or 02 (fob)
    # take 01 (bridge) if you want to make sure that the 'new state available'-flag is cleared on the Nuki if you read it out the state using this library
    myIDType = '01'
    nuki.Nuki(mac_address).authenticateUser(keypair.public_key.__bytes__(), keypair.__bytes__().hex(), myID, myIDType, name)
    return "Connected to " + mac_address

@app.route("/lock/<door>")
def lock_door(door):
    return execute_action('LOCK', door)

@app.route("/unlock/<door>")
def unlock_door(door):
    return execute_action('UNLOCK', door)

@app.route("/state/<door>")
def state(door):
    return nuki.Nuki(config[door]).readLockState().show()

@app.route("/logs/<door>")
def get_log_entries(door):
    return jsonify(nuki.Nuki(config[door]).getLogEntries(1, "%04x" % 0000))

def execute_action(type, door):
    nuki.Nuki(config[door]).lockAction(type)
    return type

