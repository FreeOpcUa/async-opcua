#!/bin/bash
set -e

echo "Starting PLC03 Server..."
ssh -o StrictHostKeyChecking=no root@2001:bc8:711:467d:dc00:1ff:fe13:5275 "killall plc-server 2>/dev/null; nohup /root/plc-server > /root/server.log 2>&1 &"

echo "Starting PLC02 Subscriber..."
ssh -o StrictHostKeyChecking=no root@2001:bc8:1d90:275b:dc00:ff:fe2c:df39 "killall plc-subscriber 2>/dev/null; nohup /root/plc-subscriber > /root/subscriber.log 2>&1 &"

echo "Starting PLC01 Publisher..."
ssh -o StrictHostKeyChecking=no root@2001:bc8:1640:7121:dc00:ff:fe6a:51d5 "killall plc-publisher 2>/dev/null; nohup /root/plc-publisher > /root/publisher.log 2>&1 &"

echo "Running PLC03 Client test..."
ssh -o StrictHostKeyChecking=no root@2001:bc8:711:467d:dc00:1ff:fe13:5275 "/root/async-opcua-simple-client --url opc.tcp://192.168.150.205:4840 > /root/client.log 2>&1 || true"

echo "Waiting for pubsub to exchange messages..."
sleep 15

echo "--- PLC02 Subscriber Logs ---"
ssh -o StrictHostKeyChecking=no root@2001:bc8:1d90:275b:dc00:ff:fe2c:df39 "cat /root/subscriber.log"

echo "--- PLC03 Server Logs (tail) ---"
ssh -o StrictHostKeyChecking=no root@2001:bc8:711:467d:dc00:1ff:fe13:5275 "tail -n 15 /root/server.log"

echo "--- PLC03 Client Logs (tail) ---"
ssh -o StrictHostKeyChecking=no root@2001:bc8:711:467d:dc00:1ff:fe13:5275 "tail -n 15 /root/client.log"

echo "Distributed test finished successfully!"
