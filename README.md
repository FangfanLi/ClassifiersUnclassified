# Classifiers Unclassified

This code has to be used with the tool developed before:

https://github.com/arashmolavi/DifferentiationDetector

The classifier_parser.py will parse the pcap file into the pickles that can be used by the replay_client and replay_server.

The user can specify what changes to be made on the trace when parsing the pcaps.

TrafficAnalysis.py can run a full analysis on the traffic by making changes in specific orders to the trace to check what triggers the classification. It needs to import a runReplay script(should be provided by user) which will run the replay for one time and return the classification result. It will then return the analysis for this trace.

To interpret the classification result:
For example, one result might be

Client analysis {0: 'removable', 1: 'removable', 2: ['Payload matter, key regions:', [[0, 3], [11]]]} 
	 Server analysis {0: 'removable', 1: 'removable'} 

This shows that there are 3 packets from the client side and 2 packets from the server side in this trace. Among the five packets, the first client packet(i.e. 0: in Client analysis) and the second client packet can be removed from the trace and would not affect the classification result. The same for the first and second packets from the server. While changing the payload in the 3rd client packet would change the classification result, where the 0,3,11 bytes of the payload are used by the classifier.