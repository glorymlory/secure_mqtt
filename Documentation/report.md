### 5823UE Security Insider Lab I - Infrastructure Security - WS2021

#### Part 4: IoT Networks - Improving the Security of MQTT

##### Dated: 10.01.2022

##### Compiled by
- **Tymofii Melnyk**
- **Hooman Shirkani**
- **Pranav Deo**


#### Exercise 1: Basics and Setup

#### 1.1 What is MQTT? Briefly describe the protocol and its purpose/relation to the IoT.

MQTT (message queuing telemetry transport) is a lightweight messaging protocol which is used in machine to machine or in IOT. The protocol is based on Pub/Sub messaging which is lightweight messaging and is preferable to IOT devices with low power of computing . A server or broker sends a message or publishes it and any other subscribers will receive the message in the form of a text message. To make these messages more secure the TLS encryption is possible after configuring and opening port number 8883.

#### 1.2 Set up your own IoT Network using MQTT Install the latest version of the Mosquitto MQTT Broker on your machine. Also install mosquitto-clients such that you can use the CLI clients ”mosquitto pub” and ”mosquitto sub”.


Installing Mosquitto MQTT broker:

```
deopranav@deopranav-kubuntu:~$ sudo apt install mosquitto
[sudo] password for deopranav: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
mosquitto is already the newest version (2.0.10-3).
The following packages were automatically installed and are no longer required:
  fonts-roboto-unhinted libjs-iscroll
Use 'sudo apt autoremove' to remove them.
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
deopranav@deopranav-kubuntu:~$ 
```

Installing Mosquitto Clients:

```
deopranav@deopranav-kubuntu:~$ sudo apt install mosquitto-clients
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
mosquitto-clients is already the newest version (2.0.10-3).
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
deopranav@deopranav-kubuntu:~$ 
```

The mosquitto clients include the `mosquitto_sub` and the `mosquitto_pub` methods which can be used to publish and subscribe to methods alike using the CLI.

Mosquitto_pub:
```
deopranav@deopranav-kubuntu:~$ mosquitto_pub --help
mosquitto_pub is a simple mqtt client that will publish a message on a single topic and exit.
mosquitto_pub version 2.0.10 running on libmosquitto 2.0.10.

Usage: mosquitto_pub {[-h host] [--unix path] [-p port] [-u username] [-P password] -t topic | -L URL}
                     {-f file | -l | -n | -m message}
                     [-c] [-k keepalive] [-q qos] [-r] [--repeat N] [--repeat-delay time] [-x session-expiry]
                     [-A bind_address] [--nodelay]
                     [-i id] [-I id_prefix]
                     [-d] [--quiet]
                     [-M max_inflight]
                     [-u username [-P password]]
                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]
                     [{--cafile file | --capath dir} [--cert file] [--key file]
                       [--ciphers ciphers] [--insecure]
                       [--tls-alpn protocol]
                       [--tls-engine engine] [--keyform keyform] [--tls-engine-kpass-sha1]]
                       [--tls-use-os-certs]
                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]
                     [--proxy socks-url]
                     [--property command identifier value]
                     [-D command identifier value]
       mosquitto_pub --help

```

Mosquitto_sub :
```
deopranav@deopranav-kubuntu:~$ mosquitto_sub --help
mosquitto_sub is a simple mqtt client that will subscribe to a set of topics and print all messages it receives.
mosquitto_sub version 2.0.10 running on libmosquitto 2.0.10.

Usage: mosquitto_sub {[-h host] [--unix path] [-p port] [-u username] [-P password] -t topic | -L URL [-t topic]}
                     [-c] [-k keepalive] [-q qos] [-x session-expiry-interval]
                     [-C msg_count] [-E] [-R] [--retained-only] [--remove-retained] [-T filter_out] [-U topic ...]
                     [-F format]
                     [-W timeout_secs]
                     [-A bind_address] [--nodelay]
                     [-i id] [-I id_prefix]
                     [-d] [-N] [--quiet] [-v]
                     [--will-topic [--will-payload payload] [--will-qos qos] [--will-retain]]
                     [{--cafile file | --capath dir} [--cert file] [--key file]
                       [--ciphers ciphers] [--insecure]
                       [--tls-alpn protocol]
                       [--tls-engine engine] [--keyform keyform] [--tls-engine-kpass-sha1]]
                       [--tls-use-os-certs]
                     [--psk hex-key --psk-identity identity [--ciphers ciphers]]
                     [--proxy socks-url]
                     [-D command identifier value]
       mosquitto_sub --help

```
#### 1.3 Set up 2 MQTT Subscribers and 2 MQTT Publishers and exchange some messages via MQTT (should contain your group name as topic or payload])




#### 1.4 Use wireshark to inspect the sent packages and explain how the protocol works.
#### 1.5 Can you spot any vulnerabilities? If so, which security goals are violated?



#### Exercise 2: Securing MQTT with TLS
Most MQTT Brokers already support the enforcement of TLS on all MQTT clients to overcome the existing security issues of the protocol.

#### 2.1 Enforce TLS on your MQTT Broker
**1. Configure the MQTT Broker such that it enforces TLS**\
**2. Setup your own CA and create certificates for the broker and all the clients**\
**3. Again, use wireshark to inspect the sent packages in order to verify that the security of MQTT has been improved.**\


**Set Up On Broker Machine** 

1. First we install openssl on machine with Broker and clients

`sudo apt-get install openssl`

2. Generate a certificate authority certificate and key.

`openssl req -x509 -nodes -sha256 -newkey rsa:2048 -subj "/OU=CA/CN=192.168.178.52"  -days 365 -keyout ca.key -out ca.crt`

**Description:**

- newkey - generates a new private key
- rsa:2048 - RSA algorithm with a 2048 bit key length
- keyout - generate a key file with the given name
- nodes - without using a passphrase
- Out - certificate file name 

The command then generates the CSR with a filename of yourdomain.csr (-out yourdomain.csr) and the information for the CSR is supplied (-subj).


3. `openssl req -nodes -sha256 -new -subj "/OU=Server/CN=192.168.178.52" -keyout server.key -out server.csr`
4. `openssl x509 -req -sha256 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365`
5. `openssl req -new -nodes -sha256 -subj "/OU=Client/CN=192.168.178.52" -out client.csr -keyout client.key`
6. `openssl x509 -req -sha256 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365`

We the need to configure `/etc/mosquitto/mosquitto.conf` file

```
pid_file /run/mosquitto/mosquitto.pid


listener 1883
#allow_anonymous false
# password_file /etc/mosquitto/passwords/auth.pwd
persistence true
persistence_location /var/lib/mosquitto/


listener 8883

cafile /etc/mosquitto/certs/ca.crt
certfile /etc/mosquitto/certs/server.crt
keyfile /etc/mosquitto/certs/server.key
require_certificate true

log_dest file /var/log/mosquitto/mosquitto.log

include_dir /etc/mosquitto/conf.d

```

The broker needs to be restarted for the new changes to be applied.
`Restart the broker `
sudo systemctl restart mosquitto.service

We can see the log with 
`sudo tail -f /var/log/mosquitto/mosquitto.log`

We can now start publishing and subscribing to the broker.

Publish

`mosquitto_pub -h 192.168.178.52 -t "test" -m "message" -p 1883 -d --cert client.crt --key client.key --cafile ca.crt`

Subscribe:

`mosquitto_sub --cafile ca.crt -h 192.168.178.52 -t "#" -p 1883 -d --cert client.crt --key client.key`

**Wireshark Inspection:**


    
#### Exercise 3: Sad News

Unfortunately, in reality most MQTT clients (small, resource constrained IoT devices) are not able to handle the computational overhead of TLS and are thus not able to perform a TLS handshake in a reasonable time. However, if the MQTT Broker is configured to only allow connections via TLS, then all devices that are not capable of using TLS cannot connect to the MQTT network. This would immensely restrict the possibilities and functionalities of IoT.

Most MQTT Brokers have therefore implemented a feature to simultaneously support multiple protocols (TLS and TCP) on different ports. This allows the enforcement of TLS on MQTT clients that are capable of handling the overhead while still being able to integrate the MQTT clients that are too resource-constrained for the usage of TLS.

#### 3.1 Configure your MQTT Broker such that it allows the connections via TCP as well as via TLS (Port 1883 and Port 8883)

It is possible to configure the MQTT broker to allow connections on multiple ports, as required. For this, we need to make a slight configuration edit and set the option `per_listener_listener true`.

The configuration changes are done in a new `.conf` file in the directory: /etc/mosquitto/conf.d

The configuration file is as follows:
```
per_listener_listener true

#Settings for connection over port 1883 with authentication
listener 1883
password_file /etc/mosquitto/auth_details/password.passwd
allow_anonymous false


#Settings for connection over TLS port 8883
listener 8883
certfile /etc/mosquitto/certs/mosquitto.crt 
cafile /etc/mosquitto/ca_certificates/ca.crt
keyfile /etc/mosquitto/certs/mosquitto.key
require_certificates true
```

#### 3.2 Connect 2 MQTT Publishers (one via port 1883 and the other one via port 8883) and 2 MQTT Subscribers (one via port 1883 and the other one via port 8883) to the broker. All clients should publish/subscribe to the same topic. Document your observations!

As required we set four clients and a mqtt broker each running on a ubuntu-server vm.

Broker   : 10.0.2.8
Client 1 : 10.0.2.1
Client 2 : 10.0.2.2
Client 3 : 10.0.2.3
Client 4 : 10.0.2.4

The two clients `publishing` are:
    - `client 1` over port 1883 with authentication
    - `client 3` over port 8883 with TLS

The two clients `subscribing` are:
    - `client 2` over port 1883 with authentication
    - `client 4` over port 8883 with TLS


*What do we observe?*

- Suppose a publisher sends a message over TLS to a topic say topic/example, and we have a subscriber on same topic which is connected via port 1883, the subscriber still receives the message.

- Suppose we have a publisher sending a message over port 1883, and a subscriber over TLS via port 8883, the subscriber will still be able to receive the message.

- That is to say, that the broker does not differentiate between a data incoming via TLS and data being send out without TLS on any given topic(s). 

- This is a security risk at large. Why? Suppose the publisher that publishes the data over TLS is doing so because the data is sensitive, and the broker is relaying the same information to a subscriber without any proper encryption, i.e without TLS, then a malicious attacker can still intercept the data and read it. So it pointless for the publisher to encrypt in the first place.

- This goes to add that there must be some sort of a method for broker to differentiate between TLS and non TLS connections and relay information published via TLS only over a TLS enabled subscriber, if a subscriber does not support TLS, then the data should not be sent to the subscriber even thought it is subscribed to a given topic.

![Publish message over port 1883, without TLS](/images/No_TLS_Publish.png) 
![Publish message over port 8883, with TLS](/images/TLS_Publish.png) 
![Subscribed Clients](/images/subscribe.png) 

 



#### 3.3 Assume that an attacker has access to the network and is able to connect to the MQTT Broker via port 1883 (no authentication). Is this a security issue? If so, what are the possible attacks that the attacker could execute?

The attacker could subscribe to any topics.
The attacker could find out what topics are present, and can publish false data to the same.
(describe more)

#### Exercise 4: Improving the Security of MQTT once again
**Try to come up with a solution to fix the existing security issues when using multiple listeners on the MQTT Broker. What you gonna do is completely up to you! Be creative and implement your solution!**

MQTT currently faces from a multitude of limitations that compromises the security of the deployed MQTT system or subsystem. Some oof which are mentioned below:

- Unlimited number of brokers
- Poor authentication. Although mosquitto does implement authentication, it is not enabled by default. Also once enabled, the credentials are passed as plaintext and can be easily inspected by a malicious party who may be monitoring network packets.
- There is no encryption of data unless TLS is used, which not all IoT devices are capable of.
- There is no implementation of data integrity and data authenticity measures.
- That said, not all devices support TLS/ SSL.
- There is no method for broker to differentiate data it received, i.e which data should be given priority, which data is more sensitive in nature and should only be sent on secure channels.
- Not too often, the broker is a single point of failure and this could cause issues, if the broker stops working or is the target of a DDos attack.

Some ways how this could be abused:

- Malicious publishers may publish non-sense data over a broker that is not deployed securely (I.e has no authentication or if credentials were to leak by someone having access to network and simply inspecting mqtt packets.)
- Malicious subscribers may subscribe to any topic being published by broker ( using `#`), and potentially access sensitive data. Sensitive data could be data from a smart home such as temperature readings, power consumption readings etc, or from a smart vehicle systems such as engine rotations (RPM), car speeds, braking time etc.
- It would prove even more disastrous if someone were to be able to publish false data to such topics and these data are used by end system to function.


#### Our Implementation:

Our general idea is to implement the following:

1. Enforce Authentication between clients and brokers.
2. Encrypt the authentication messages, such that credentials are not leaked over the a simple network packet scan.
3. Use asymmetric keys to encrypt the data between clients and broker so as to enforce data integrity. 

**Encryption of Authentication Message**

- We encrypt all the authentication messages between all clients and broker.
- We use the `Speck80 Block Cipher` to encrypt all the messages.
- `Speck80` has been used as it is a lightweight block cipher that can be handled by most IoT devices while also providing substantial security measures.
- The assumption we make: That the `broker` and `client` and already aware of the key used for encryption and decryption.