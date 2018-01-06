#!/bin/bash

screen -X -S analyzer quit
screen -X -S replay quit

cd /home/ubuntu/DD/src/

#screen -S replay -d -m sudo python /home/ubuntu/DD/src/replay_server.py --ConfigFile=/home/ubuntu/DD/src/configs.cfg --original_ports=True

screen -S analyzer -d -m sudo python replay_analyzerServer.py --ConfigFile=configs.cfg --original_ports=True

screen -S replay -d -m sudo python replay_server.py --ConfigFile=configs.cfg --original_ports=True
