package Integrity;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
//import org.apache.commons.lang3.StringUtils;


public class AsymmetricCryptography {
	private Cipher cipher;

	public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException {
		this.cipher = Cipher.getInstance("RSA");
		System.out.println("CREATED");
	}

	public PrivateKey getPrivate(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public PublicKey getPublic(String filename) throws Exception {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public void encryptFile(byte[] input, File output, PrivateKey key) 
		throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	public void decryptFile(byte[] input, File output, PublicKey key) 
		throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	private void writeToFile(File output, byte[] toWrite)
			throws IllegalBlockSizeException, BadPaddingException, IOException {
		FileOutputStream fos = new FileOutputStream(output);
		fos.write(toWrite);
		fos.flush();
		fos.close();
	}

	public String encryptText(String msg, PrivateKey key) 
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException, 
			BadPaddingException, InvalidKeyException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	public String decryptText(String msg, PublicKey key)
			throws InvalidKeyException, UnsupportedEncodingException, 
			IllegalBlockSizeException, BadPaddingException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
	}

	public byte[] getFileInBytes(File f) throws IOException {
		FileInputStream fis = new FileInputStream(f);
		byte[] fbytes = new byte[(int) f.length()];
		fis.read(fbytes);
		fis.close();
		return fbytes;
	}
//
//	public static void main(String[] args) throws Exception {
//		AsymmetricCryptography ac = new AsymmetricCryptography();
//		PrivateKey privateKey = ac.getPrivate("KeyPair/privateKey");
//		PublicKey publicKey = ac.getPublic("KeyPair/publicKey");
//
//		String msg = "Cryptography is fun!";
//
//		// hash message
//	    int hash = msg.hashCode();
//		String hash_msg = String.valueOf(hash);
//
//
//		//combine : hash + "." + message to give the payload
//		String payload =  hash_msg + "." + msg  ;
//
//		//encrypt payload
//		String encrypted_msg = ac.encryptText(payload, privateKey);
//
//		//decrypt payload
//		String decrypted_msg = ac.decryptText(encrypted_msg, publicKey);
//
//
//		//divide the decrypt message
//
//		String[] parts = decrypted_msg.split(".", 2 );
//		String part1 = parts[0]; // 004-
//		String part2 = parts[1]; // 034556
//
//		//hash new payload to compare:
//		int new_hash = part2.hashCode();
//		String new_hash_msg = String.valueOf(new_hash);
//
//
//		// print results
//		System.out.println("Original Message: " + msg + "\nHashed Message: " + hash_msg +
//		"\n Entire Payload: " + payload+
//			"\nEncrypted Message: " + encrypted_msg
//			+ "\nDecrypted Message: " + decrypted_msg
//			+ "\nString part 1 " + part1
//			+ "\nString part 2 " + part2
//			+ "\nNew hash " + new_hash_msg
//			);
//
//		if (new File("KeyPair/text.txt").exists()) {
//			ac.encryptFile(ac.getFileInBytes(new File("KeyPair/text.txt")),
//				new File("KeyPair/text_encrypted.txt"),privateKey);
//			ac.decryptFile(ac.getFileInBytes(new File("KeyPair/text_encrypted.txt")),
//				new File("KeyPair/text_decrypted.txt"), publicKey);
//		} else {
//			System.out.println("Create a file text.txt under folder KeyPair");
//		}
//	}
}
