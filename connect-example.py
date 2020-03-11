import nuki
from nacl.public import PrivateKey
import sys

# generate the private key which must be kept secret
keypair = PrivateKey.generate()
myPublicKey = keypair.public_key.__bytes__()
myPrivateKeyHex = keypair.__bytes__().hex()
myID = 50
# id-type = 00 (app), 01 (bridge) or 02 (fob)
# take 01 (bridge) if you want to make sure that the 'new state available'-flag is cleared on the Nuki if you read it out the state using this library
myIDType = '01'
nuki.Nuki(sys.argv[0]).authenticateUser(myPublicKey, myPrivateKeyHex, myID, myIDType, sys.argv[1])

