/*
 * AuthCodeBlock.java
 *
 * 5 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.decrypt;
import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.encrypt;
import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.generateRnd;
import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.generateSessionKey;
import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.importSessionKey;
import static it.pagopa.swclient.mil.idpay.authcode.Util.bytes2hex;
import static it.pagopa.swclient.mil.idpay.authcode.Util.fix;
import static it.pagopa.swclient.mil.idpay.authcode.Util.xor;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateAuthCode;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateAuthCodeBlockData;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateEpochMill;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateEurocents;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateNis;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validatePrivateKey;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validatePublicKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * 
 * @author Antonio Tarricone
 */
public class AuthCodeBlock {
	/**
	 * 
	 */
	private AuthCodeBlock() {
	}

	/**
	 * @formatter:off
	 * 
	 * +-----------+-----------+--------+
	 * | eurocents | epochMill | 00...0 | -> 128 bits
	 * +-----------+-----------+--------+
	 * 
	 * @formatter:on
	 * 
	 * @param eurocents
	 * @param epochMill
	 * @return
	 */
	private static byte[] buildIV(long eurocents, long epochMill) {
		StringBuilder buf = new StringBuilder(Long.toString(eurocents))
			.append(Long.toString(epochMill));

		fix(buf, '0', 32);

		return Util.hex2bytes(buf.toString());
	}

	/**
	 * @formatter:off
	 * 
	 * +---+---------------+-----------+--------+----------------+
	 * | 4 | auth code len | auth code | ff...f | 64 random bits | -> 128 bits
	 * +---+---------------+-----------+--------+----------------+
	 * 
	 * @formatter:on
	 * 
	 * @param authCode
	 * @param rnd
	 * @return
	 */
	private static byte[] buildDataBlock1(String authCode, byte[] rnd) {
		StringBuilder buf = new StringBuilder("4")
			.append(authCode.length())
			.append(authCode);

		fix(buf, 'f', 16);

		byte[] temp = Util.hex2bytes(buf.toString()); // 8 bytes

		byte[] dataBlock1 = new byte[16];
		System.arraycopy(temp, 0, dataBlock1, 0, 8);
		System.arraycopy(rnd, 0, dataBlock1, 8, 8);

		return dataBlock1;
	}

	/**
	 * @formatter:off
	 * 
	 * +---+-----+--------+
	 * | 0 | nis | 00...0 | -> 128 bits
	 * +---+-----+--------+
	 *   ^
	 *   |
	 *   +-- (NIS length - 12)
	 * 
	 * @formatter:on
	 * 
	 * @param nis
	 * @return
	 */
	private static byte[] buildDataBlock2(String nis) {
		StringBuilder buf = new StringBuilder(Integer.toString(nis.length() - 12))
			.append(nis);

		fix(buf, '0', 32);

		return Util.hex2bytes(buf.toString());
	}

	/**
	 * @formatter:off
	 * 
	 * +-----------+-----------+--------+                   IV
	 * | eurocents | epochMill | 00...0 | ---------------------------------------+------------------------------+
	 * +-----------+-----------+--------+                                        |                              |
	 *                                                                           v                              |
	 * +---+---------------+-----------+--------+----------------+  DATA  +-------------+                       |
	 * | 4 | auth code len | auth code | ff...f | 64 random bits | -----> | Enc AES/CBC | <------- KEY          |
	 * +---+---------------+-----------+--------+----------------+        +-------------+           |           |
	 *                                                                           |                  |           |
	 *                                                                           v                  v           |
	 * +---+-----+--------+                                                   +-----+  DATA  +-------------+    |
	 * | 0 | nis | 00...0 | ------------------------------------------------> | XOR | -----> | Enc AES/CBC | <--+
	 * +---+-----+--------+                                                   +-----+        +-------------+
	 *   ^                                                                                          |
	 *   |                                                                                          v
	 *   +-- (NIS length - 12)                                                             +-----------------+
	 *                                                                                     | AUTH CODE BLOCK |
	 *                                                                                     +-----------------+
	 * 
	 * @formatter:on
	 * 
	 * @param eurocents
	 * @param epochMill
	 * @param authCode
	 * @param nis
	 * @param masterKey
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 */
	public static AuthCodeBlockData getAuthCodeBlock(long eurocents, long epochMill, String authCode, String nis, RSAPublicKey masterKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		validateEurocents(eurocents);
		validateEpochMill(epochMill);
		validateAuthCode(authCode);
		validateNis(nis);
		validatePublicKey(masterKey);

		SecretKey sessionKey = generateSessionKey();
		byte[] iv = buildIV(eurocents, epochMill);
		byte[] rnd = generateRnd();
		byte[] dataBlock1 = buildDataBlock1(authCode, rnd);
		byte[] encDataBlock1 = encrypt(dataBlock1, sessionKey, iv);
		byte[] dataBlock2 = buildDataBlock2(nis);
		byte[] clearAuthCodeBlock = xor(encDataBlock1, dataBlock2);
		byte[] authCodeBlock = encrypt(clearAuthCodeBlock, sessionKey, iv);
		byte[] encSessionKey = encrypt(sessionKey.getEncoded(), masterKey);

		return new AuthCodeBlockData(encSessionKey, authCodeBlock);
	}

	/**
	 * @formatter:off
	 * 
	 * +-----------+-----------+--------+             IV
	 * | eurocents | epochMill | 00...0 | ---------+------------------------------+
	 * +-----------+-----------+--------+          |                              |
	 *                                             |                              |
	 *                                             v                              |
	 * +-----------------+                  +-------------+                       |
	 * | AUTH CODE BLOCK | ---------------> | Dec AES/CBC | <------- KEY          |
	 * +-----------------+                  +-------------+           |           |
	 *                                             |                  |           |
	 *                                             v                  v           |
	 * +---+-----+--------+                     +-----+  DATA  +-------------+    |
	 * | 0 | nis | 00...0 | ------------------> | XOR | -----> | Dec AES/CBC | <--+
	 * +---+-----+--------+                     +-----+        +-------------+
	 *                                                                |
	 *                                                                |
	 * +---+---------------+-----------+--------+----------------+    |
	 * | 4 | auth code len | auth code | ff...f | 64 random bits | <--+
	 * +---+---------------+-----------+--------+----------------+
	 * 
	 * @formatter:on
	 * 
	 * @param eurocents
	 * @param epochMill
	 * @param authCodeBlockData
	 * @param nis
	 * @param masterKey
	 * @return
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static String getAuthCode(long eurocents, long epochMill, AuthCodeBlockData authCodeBlockData, String nis, RSAPrivateKey masterKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		validateEurocents(eurocents);
		validateEpochMill(epochMill);
		validateAuthCodeBlockData(authCodeBlockData);
		validateNis(nis);
		validatePrivateKey(masterKey);
		authCodeBlockData.validate();

		byte[] sessionKeyBytes = decrypt(authCodeBlockData.getEncSessionKey(), masterKey);
		SecretKey sessionKey = importSessionKey(sessionKeyBytes);
		byte[] iv = buildIV(eurocents, epochMill);
		byte[] clearAuthCodeBlock = decrypt(authCodeBlockData.getAuthCodeBlock(), sessionKey, iv);
		byte[] dataBlock2 = buildDataBlock2(nis);
		byte[] encDataBlock1 = xor(clearAuthCodeBlock, dataBlock2);
		byte[] dataBlock1 = decrypt(encDataBlock1, sessionKey, iv);

		int authCodeLen = dataBlock1[0] & 0xf;
		String dataBlock1Str = bytes2hex(dataBlock1);
		return dataBlock1Str.substring(2, 2 + authCodeLen);
	}
}