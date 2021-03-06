# import logging
# import asyncio
# import os
# from hbmqtt.broker import Broker
# from hbmqtt.client import MQTTClient, ConnectException
# from hbmqtt.mqtt.constants import QOS_0, QOS_1, QOS_2

# logger = logging.getLogger(__name__)

# config = {
#     'listeners': {
#         'default': {
#             'type': 'tcp',
#             'bind': 'localhost:1883',
#         },
#         # 'ws-mqtt': {
#         #     'bind': '127.0.0.1:8080',
#         #     'type': 'ws',
#         #     'max_connections': 10,
#         # },
#     },
#     'sys_interval': 10,
#     'auth': {
#         'allow-anonymous': True,
#         # 'password-file': os.path.join(os.path.dirname(os.path.realpath(__file__)), "passwd"),
#         'plugins': [
#             'auth_file', 'auth_anonymous'
#         ]
#     },
#     'topic-check': {
#         'enabled': False,
#         'plugins':['topic_taboo']
#     }
# }

# broker = Broker(config)


# @asyncio.coroutine
# def test_coro():
#     yield from broker.start()
#     #yield from asyncio.sleep(5)
#     #yield from broker.shutdown()

# @asyncio.coroutine
# def brokerGetMessage():
#     C = MQTTClient()
#     yield from C.connect('mqtt://localhost:1883/')
    
#     print("inside subscription")
#     yield from C.subscribe([
#         ("group/test", QOS_0),
#         ("group/test", QOS_2),
#         ("group/test", QOS_1),
#         ("group/verify", QOS_1)
#     ])

   
#     logger.info('Subscribed!')
#     try:
#         for i in range(1,100):
#             message = yield from C.deliver_message()
#             packet = message.publish_packet
#             print(str(packet.payload))
#             print(packet.payload.data.decode('utf-8'))
#     except ClientException as ce:
#         logger.error("Client exception : %s" % ce)

# if __name__ == '__main__':
#     formatter = "[%(asctime)s] :: %(levelname)s :: %(name)s :: %(message)s"
#     #formatter = "%(asctime)s :: %(levelname)s :: %(message)s"
#     logging.basicConfig(level=logging.INFO, format=formatter)
#     asyncio.get_event_loop().run_until_complete(test_coro())
#     asyncio.get_event_loop().run_until_complete(brokerGetMessage())
#     asyncio.get_event_loop().run_forever()

import logging
import asyncio
import os
from hbmqtt.broker import Broker

logger = logging.getLogger(__name__)

config = {
    'listeners': {
        'default': {
            'type': 'tcp',
            'bind': 'localhost:1883',
        },
        # 'ws-mqtt': {
        #     'bind': '127.0.0.1:8080',
        #     'type': 'ws',
        #     'max_connections': 10,
        # },
    },
    'sys_interval': 10,
    'auth': {
        'allow-anonymous': True,
        'password-file': os.path.join(os.path.dirname(os.path.realpath(__file__)), "passwd"),
        'plugins': [
            'auth_file', 'auth_anonymous'
        ]

    },
    'topic-check': {
        'enabled': True,
        'plugins': [
            'topic_taboo'
        ]
    }
}

broker = Broker(config)


@asyncio.coroutine
def test_coro():
    yield from broker.start()


if __name__ == '__main__':
    formatter = "[%(asctime)s] :: %(levelname)s :: %(name)s :: %(message)s"
    logging.basicConfig(level=logging.INFO, format=formatter)
    asyncio.get_event_loop().run_until_complete(test_coro())
    asyncio.get_event_loop().run_forever()