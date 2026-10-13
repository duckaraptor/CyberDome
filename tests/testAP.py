import os
import sys

# Make the repo root importable, wherever this script is started from
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyberdome.networking import AccessProxyNode

#Create an instance of this node
node_1 = AccessProxyNode("127.0.0.1", 8001)

#Start the node
node_1.start()

debug = False

node_1.debug =debug

#Connect with node 4
node_1.connect_with_node('127.0.0.1',8004)

try:
    #Start a loop
    while(True):

        userInput = input("\nType 'exit' to stop the node")

        if(userInput == 'exit'):
            break

except KeyboardInterrupt:
    print("\nKeyboard interrupt received. Exiting...")

finally:
    node_1.stop()

