import Integrity.AsymmetricCryptography;
import org.eclipse.paho.client.mqttv3.*;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;


/* do NOT remove
 * mvn clean package
 * mvn exec:java -Dexec.mainClass="MqttPublisher"
 * */

public class MqttSubscriber implements MqttCallback {

    /**
     * The broker url.
     */
    private static final String brokerUrl = "tcp://0.0.0.0:1883";

    /**
     * The client id.
     */
    private static final String clientId = "clientId";

    /**
     * The topic.
     */
    private static final String topic = "test";

    public static void main(String[] args) {
        System.out.println("Subscriber running");
        new MqttSubscriber().subscribe(topic);
    }

    public void subscribe(String topic) {
        //	logger file name and pattern to log
        MemoryPersistence persistence = new MemoryPersistence();
        try {
            MqttClient sampleClient = new MqttClient(brokerUrl, clientId, persistence);
            MqttConnectOptions connOpts = new MqttConnectOptions();
            connOpts.setCleanSession(true);

            System.out.println("checking");
            System.out.println("Mqtt Connecting to broker: " + brokerUrl);

            sampleClient.connect(connOpts);
            System.out.println("Mqtt Connected");

            sampleClient.setCallback(this);
            sampleClient.subscribe(topic);

            System.out.println("Subscribed");
            System.out.println("Listening");

        } catch (MqttException me) {
            System.out.println(me);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void checkMsgIntegrityAndDecrypt(String msg) {
        try {
            AsymmetricCryptography ac = new AsymmetricCryptography();
            Path path = Paths.get("KeyPair/publicKey");
            System.out.println("\nPATH TP FILE: \n" + path.toAbsolutePath());
            PublicKey publicKey = ac.getPublic(path.toAbsolutePath().toString());

            //decrypt payload
            String decrypted_msg = ac.decryptText(msg, publicKey);
            //divide the decrypt message
            String[] parts = decrypted_msg.split("\\.", 2);
            String part1 = parts[0]; // 004-
            String part2 = parts[1]; // 034556

            //hash new payload to compare:
            int hash = part2.hashCode();
            String hash_msg = String.valueOf(hash);
            int new_hash = part2.hashCode();
            String new_hash_msg = String.valueOf(new_hash);

            // print results
            System.out.println("Original Message: " + msg + "\nHashed Message: " + hash_msg +
                    "\n Entire Payload: " + msg +
                    "\nEncrypted Message: " + part2
                    + "\nDecrypted Message: " + decrypted_msg
                    + "\nString part 1 " + part1
                    + "\nString part 2 " + part2
                    + "\nNew hash " + new_hash_msg
            );

//            HERE WE CAN COMPARE THE HASHES AND GIVE APPROPRIATE RESPONSE ON INTEGRITY VIOLATION

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //Called when the client lost the connection to the broker
    public void connectionLost(Throwable arg0) {
    }

    //Called when a outgoing publish is complete
    public void deliveryComplete(IMqttDeliveryToken arg0) {
    }

    @Override
    public void messageArrived(String topic, MqttMessage message) {
        checkMsgIntegrityAndDecrypt(message.toString());
        System.out.println("| Topic:" + topic);
        System.out.println("| Message: " + message.toString());
        System.out.println("-------------------------------------------------");
    }
}
