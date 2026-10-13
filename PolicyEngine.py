import signal
import sys
from threading import Event

sys.path.insert(0, '..') # Import the files where the modules are located

from cyberdome.networking import PolicyEngineNode

#Create an instance of this node
node_3 = PolicyEngineNode("127.0.0.1", 8003)

#Start the node
node_3.start()
node_3.connect_with_node('127.0.0.1',8002)
node_3.connect_with_node('127.0.0.1',8004)
node_3.connect_with_node('127.0.0.1', 8001)
shutdown_event = Event()
signal.signal(signal.SIGTERM, lambda _signum, _frame: shutdown_event.set())

debug = False

node_3.debug = debug

try:
    if sys.stdin.isatty():
        while(True):
            userInput = input("\nType 'exit' to stop the policy engine")

            if(userInput == 'exit'):
                break
    else:
        shutdown_event.wait()
except KeyboardInterrupt:
    print("\nKeyboard interrupt received. Exiting...")
finally:
    node_3.stop()
