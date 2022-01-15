import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MqttDefaultFilePersistence;
import speck.Encrypt;
import edu.rit.util.Hex;

import java.util.Arrays;


/* do NOT remove
* mvn clean package
* mvn exec:java -Dexec.mainClass="MqttPublisher"
* */

public class MqttPublisher {
    private static final String USERNAME = "testuser";
    private static final String PASSWORD = "passwd";

    public static void main(String[] args) {

        String topic        = "test";
        String content      = "HelloTim";
        int qos             = 0;
        String broker       = "tcp://0.0.0.0:1883";
        String clientId     = "1234";
        MqttDefaultFilePersistence subDataStore = new MqttDefaultFilePersistence("/tmp/sub");

        String encryptedPayload = encryptStr(content);
        String encryptedLogin = encryptStr(USERNAME);
        String encryptedPass = encryptStr(PASSWORD);

        try {
            MqttClient sampleClient = new MqttClient(broker, clientId, subDataStore);
            MqttConnectOptions connOpts = new MqttConnectOptions();
            connOpts.setUserName(encryptedLogin);
            connOpts.setPassword(encryptedPass.toCharArray());
            connOpts.setCleanSession(true);
            connOpts.setKeepAliveInterval(5);
            System.out.println("Connecting to broker: " + broker);
            sampleClient.connect(connOpts);
            System.out.println("Connected");
            System.out.println("Publishing message: " + encryptedPayload);
            MqttMessage message = new MqttMessage(encryptedPayload.getBytes());
            message.setQos(qos);
            sampleClient.publish(topic, message);
            System.out.println("Message published");
            sampleClient.disconnect();
            System.out.println("Disconnected");
            System.exit(0);
        } catch (MqttException me) {
            System.out.println("reason " + me.getReasonCode());
            System.out.println("msg " + me.getMessage());
            System.out.println("loc " + me.getLocalizedMessage());
            System.out.println("cause " + me.getCause());
            System.out.println("excep " + me);
            me.printStackTrace();
        }
    }

    private static String encryptStr(String content) {
        byte[] key1 =Hex.toByteArray("502e50ca60fa6c7c");
        byte[] plaintext1 = content.getBytes();
        System.out.println("\n PLAINTEXT BYTES : " +  Arrays.toString(plaintext1));
        Encrypt s1= new Encrypt(key1, plaintext1);
        s1.setKey(key1);
        s1.key_schedule();
        s1.encrypt(plaintext1);
        String encryptedPayload = Hex.toString(plaintext1);
        System.out.println("ENCRYPTED: " + encryptedPayload); // printing the ciphertext  output
        return encryptedPayload;
    }
}
