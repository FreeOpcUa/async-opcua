#!/bin/bash
set -e
echo "Deploying to PLC01..."
scp -o StrictHostKeyChecking=no target/x86_64-unknown-linux-gnu/release/plc-publisher root@[2001:bc8:1640:7121:dc00:ff:fe6a:51d5]:/root/
echo "Deploying to PLC02..."
scp -o StrictHostKeyChecking=no target/x86_64-unknown-linux-gnu/release/plc-subscriber root@[2001:bc8:1d90:275b:dc00:ff:fe2c:df39]:/root/
echo "Deploying to PLC03..."
scp -o StrictHostKeyChecking=no target/x86_64-unknown-linux-gnu/release/plc-server root@[2001:bc8:711:467d:dc00:1ff:fe13:5275]:/root/
scp -o StrictHostKeyChecking=no target/x86_64-unknown-linux-gnu/release/async-opcua-simple-client root@[2001:bc8:711:467d:dc00:1ff:fe13:5275]:/root/
echo "Done deploying!"
