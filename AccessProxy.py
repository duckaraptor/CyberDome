import signal
import sys
from threading import Event

sys.path.insert(0, '..') # Import the files where the modules are located

from Networking import Networking

#Create an instance of this node
node_1 = Networking("127.0.0.1", 8001, 1)

#Start the node
node_1.start()

shutdown_event = Event()
signal.signal(signal.SIGTERM, lambda _signum, _frame: shutdown_event.set())

debug = False

node_1.debug =debug

#Connect with node 2
node_1.connect_with_node('127.0.0.1', 8002)
node_1.connect_with_node('127.0.0.1',8003)
node_1.connect_with_node('127.0.0.1',8004)

try:
    if sys.stdin.isatty():
        while(True):
            userInput = input("\nType 'exit' to stop the Access Proxy...")

            if(userInput == 'exit'):
                break
    else:
        shutdown_event.wait()

except KeyboardInterrupt:
    print("\nKeyboard interrupt received. Exiting...")

finally:
    node_1.stop()
