/*
 * Validator.java
 *
 * 6 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

/**
 * 
 * @author Antonio Tarricone
 */
public class Validator {
	/*
	 * 
	 */
	private static final int SKEW = 5 * 60000;

	/**
	 * 
	 */
	private Validator() {
	}

	/**
	 * 
	 * @param eurocents
	 */
	static void validateEurocents(long eurocents) {
		if (eurocents < 0)
			throw new IllegalArgumentException("eurocents must be greater than or equal to 0");

		if (eurocents > 99999999999L)
			throw new IllegalArgumentException("eurocents must be less than or equal to 99999999999");
	}

	/**
	 * 
	 * @param epochMill
	 */
	static void validateEpochMill(long epochMill) {
		long now = Instant.now().toEpochMilli();
		long min = now - SKEW;
		long max = now + SKEW;

		if (epochMill > max || epochMill < min)
			throw new IllegalArgumentException(String.format("epochMill must be between %d and %d", min, max));
	}

	/**
	 * 
	 * @param authCode
	 */
	static void validateAuthCode(String authCode) {
		if (authCode == null)
			throw new IllegalArgumentException("authCode must not be null");
		if (!authCode.matches("^\\d{4,12}$"))
			throw new IllegalArgumentException("authCode must match ^\\d{4,12}$");
	}

	/**
	 * 
	 * @param authCodeBlockData
	 */
	static void validateAuthCodeBlockData(AuthCodeBlockData authCodeBlockData) {
		if (authCodeBlockData == null)
			throw new IllegalArgumentException("authCodeBlockData must not be null");
	}

	/**
	 * 
	 * @param nis
	 */
	static void validateNis(String nis) {
		if (nis == null)
			throw new IllegalArgumentException("nis must not be null");
		if (!nis.matches("^\\d{12}$"))
			throw new IllegalArgumentException("nis must match ^\\d{12}$");
	}

	/**
	 * 
	 * @param publicKey
	 */
	static void validatePublicKey(RSAPublicKey publicKey) {
		if (publicKey == null)
			throw new IllegalArgumentException("publicKey must not be null");
	}

	/**
	 * 
	 * @param publicKey
	 */
	static void validatePrivateKey(RSAPrivateKey privateKey) {
		if (privateKey == null)
			throw new IllegalArgumentException("privateKey must not be null");
	}
}