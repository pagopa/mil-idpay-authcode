/*
 * SecurityUtil.java
 *
 * 6 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author Antonio Tarricone
 */
public class SecurityUtil {
	/**
	 * 
	 */
	private SecurityUtil() {
	}

	/**
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	static byte[] generateRnd() throws NoSuchAlgorithmException {
		byte[] rnd = new byte[8];
		SecureRandom.getInstanceStrong().nextBytes(rnd);
		return rnd;
	}

	/**
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	static SecretKey generateSessionKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256);
		return keyGenerator.generateKey();
	}

	/**
	 * 
	 * @param sessionKey
	 * @return
	 */
	static SecretKey importSessionKey(byte[] sessionKey) {
		return new SecretKeySpec(sessionKey, "AES");
	}

	/**
	 * 
	 * @param data
	 * @param key
	 * @param iv
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	static byte[] encrypt(byte[] data, SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(
			Cipher.ENCRYPT_MODE,
			key,
			new IvParameterSpec(iv));
		return cipher.doFinal(data);
	}

	/**
	 * 
	 * @param data
	 * @param key
	 * @param iv
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	static byte[] decrypt(byte[] data, SecretKey key, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(
			Cipher.DECRYPT_MODE,
			key,
			new IvParameterSpec(iv));
		return cipher.doFinal(data);
	}

	/**
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	static byte[] encrypt(byte[] data, RSAPublicKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-512andMGF1Padding");
		cipher.init(
			Cipher.ENCRYPT_MODE,
			key);
		return cipher.doFinal(data);
	}

	/**
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	static byte[] decrypt(byte[] data, RSAPrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA-512andMGF1Padding");
		cipher.init(
			Cipher.DECRYPT_MODE,
			key);
		return cipher.doFinal(data);
	}
}