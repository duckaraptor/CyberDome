import signal
import sys
from threading import Event

sys.path.insert(0, '..') # Import the files where the modules are located

from cyberdome.networking import TrustEngineNode

#Create an instance of this node
node_2 = TrustEngineNode("127.0.0.1", 8002)

#Start the node2
node_2.start()

shutdown_event = Event()
signal.signal(signal.SIGTERM, lambda _signum, _frame: shutdown_event.set())

debug = False

node_2.debug = debug

#Connect with node 1
node_2.connect_with_node('127.0.0.1', 8003)
node_2.connect_with_node('127.0.0.1',8001)

try:
    if sys.stdin.isatty():
        while(True):
            userInput = input("\nType 'exit' to end the Trust engine...")

            if(userInput == 'exit'):
                break
    else:
        shutdown_event.wait()
except KeyboardInterrupt:
    print("\nKeyboard interrupt received. Exiting...")
finally:
    node_2.stop()
