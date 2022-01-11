import logging
import asyncio

from hbmqtt.client import MQTTClient, ConnectException
from hbmqtt.mqtt.constants import QOS_0, QOS_1, QOS_2


#
# This sample shows how to publish messages to broker using different QOS
# Debug outputs shows the message flows

logger = logging.getLogger(__name__)

@asyncio.coroutine
def test_coro():
    C = MQTTClient()
    yield from C.connect('mqtt://localhost:1883/')
    tasks = [
        asyncio.ensure_future(C.publish('test', b'TEST MESSAGE WITH QOS_1',  qos=QOS_1)),
    ]
    yield from asyncio.wait(tasks)
    logger.info("messages published")
    yield from C.disconnect()

if __name__ == '__main__':
    formatter = "[%(asctime)s] %(name)s {%(filename)s:%(lineno)d} %(levelname)s - %(message)s"
    formatter = "%(message)s"
    logging.basicConfig(level=logging.DEBUG, format=formatter)
    asyncio.get_event_loop().run_until_complete(test_coro())