/*
 * AuthCodeBlockDataTest.java
 *
 * 11 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * 
 */
class AuthCodeBlockDataTest {
	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.AuthCodeBlockData#validate()}.
	 */
	@Test
	void testValidateAuthCodeBlockNull() {
		assertThrows(IllegalArgumentException.class, () -> new AuthCodeBlockData(new byte[] {}, null));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.AuthCodeBlockData#validate()}.
	 */
	@Test
	void testValidateAuthCodeBlockBadLength() {
		assertThrows(IllegalArgumentException.class, () -> new AuthCodeBlockData(new byte[] {}, new byte[] {}));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.AuthCodeBlockData#validate()}.
	 */
	@Test
	void testValidateEncSessionKeyNull() {
		assertThrows(IllegalArgumentException.class, () -> new AuthCodeBlockData(null, new byte[] {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
		}));
	}
}