/*
 * ValidatorTest.java
 *
 * 11 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateAuthCode;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateAuthCodeBlockData;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateEpochMill;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateEurocents;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validateNis;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validatePrivateKey;
import static it.pagopa.swclient.mil.idpay.authcode.Validator.validatePublicKey;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;

import org.junit.jupiter.api.Test;

/**
 * 
 * @author Antonio Tarricone
 */
class ValidatorTest {
	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateEurocents(long)}.
	 */
	@Test
	void testValidateEurocentsNegativeAmount() {
		assertThrows(IllegalArgumentException.class, () -> validateEurocents(-1));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateEurocents(long)}.
	 */
	@Test
	void testValidateEurocentsAmountTooLarge() {
		assertThrows(IllegalArgumentException.class, () -> validateEurocents(100000000000L));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateEpochMill(long)}.
	 */
	@Test
	void testValidateEpochMillBelowMin() {
		long epochMill = Instant.now().toEpochMilli() - 6 * 60000;
		assertThrows(IllegalArgumentException.class, () -> validateEpochMill(epochMill));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateEpochMill(long)}.
	 */
	@Test
	void testValidateEpochMillAboveMax() {
		long epochMill = Instant.now().toEpochMilli() + 6 * 60000;
		assertThrows(IllegalArgumentException.class, () -> validateEpochMill(epochMill));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateEpochMill(long)}.
	 */
	@Test
	void testValidateEpochMillOk() {
		long epochMill = Instant.now().toEpochMilli();
		assertDoesNotThrow(() -> validateEpochMill(epochMill));
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateAuthCode(java.lang.String)}.
	 */
	@Test
	void testValidateAuthCodeNull() {
		assertThrows(IllegalArgumentException.class, () -> validateAuthCode(null));
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateAuthCode(java.lang.String)}.
	 */
	@Test
	void testValidateAuthCodeBadPattern() {
		assertThrows(IllegalArgumentException.class, () -> validateAuthCode("test"));
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateAuthCodeBlockData(it.pagopa.swclient.mil.idpay.authcode.AuthCodeBlockData)}.
	 */
	@Test
	void testValidateAuthCodeBlockData() {
		assertThrows(IllegalArgumentException.class, () -> validateAuthCodeBlockData(null));
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateNis(java.lang.String)}.
	 */
	@Test
	void testValidateNisNull() {
		assertThrows(IllegalArgumentException.class, () -> validateNis(null));
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validateNis(java.lang.String)}.
	 */
	@Test
	void testValidateNisBadPattern() {
		assertThrows(IllegalArgumentException.class, () -> validateNis("test"));
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validatePublicKey(java.security.interfaces.RSAPublicKey)}.
	 */
	@Test
	void testValidatePublicKey() {
		assertThrows(IllegalArgumentException.class, () -> validatePublicKey(null));
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Validator#validatePrivateKey(java.security.interfaces.RSAPrivateKey)}.
	 */
	@Test
	void testValidatePrivateKey() {
		assertThrows(IllegalArgumentException.class, () -> validatePrivateKey(null));
	}
}