import asyncio
from asyncua import Client

async def main():
    url = "opc.tcp://192.168.150.205:4840/"
    try:
        async with Client(url=url) as client:
            node = client.get_node("ns=0;i=2259")
            value = await node.read_value()
            print(f"SUCCESS: Connected to {url}, Server State: {value}")
    except Exception as e:
        print(f"FAILED to connect: {e}")

if __name__ == "__main__":
    asyncio.run(main())
