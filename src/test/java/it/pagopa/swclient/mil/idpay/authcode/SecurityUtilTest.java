/*
 * SecurityUtilTest.java
 *
 * 11 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.generateRnd;
import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.generateSessionKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

/**
 * 
 */
class SecurityUtilTest {

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.SecurityUtil#generateRnd()}.
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	void testGenerateRnd() throws NoSuchAlgorithmException {
		byte[] rnd = generateRnd();
		assertEquals(8, rnd.length);
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.SecurityUtil#generateSessionKey()}.
	 * 
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	void testGenerateSessionKey() throws NoSuchAlgorithmException {
		SecretKey sessionKey = generateSessionKey();
		assertNotNull(sessionKey);
	}
}
