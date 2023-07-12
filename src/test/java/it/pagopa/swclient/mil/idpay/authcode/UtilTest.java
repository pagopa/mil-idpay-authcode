/*
 * UtilTest.java
 *
 * 11 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import static it.pagopa.swclient.mil.idpay.authcode.Util.bytes2hex;
import static it.pagopa.swclient.mil.idpay.authcode.Util.fix;
import static it.pagopa.swclient.mil.idpay.authcode.Util.hex2bytes;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * 
 * @author Antonio Tarricone
 */
class UtilTest {
	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Util#fix(java.lang.StringBuilder, char, int)}.
	 */
	@Test
	void testFixLenAlreadyOk() {
		StringBuilder buf = new StringBuilder("123456");
		fix(buf, '0', 6);
		assertEquals(6, buf.length());
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.Util#fix(java.lang.StringBuilder, char, int)}.
	 */
	@Test
	void testFixTooLong() {
		StringBuilder buf = new StringBuilder("123456");
		fix(buf, '0', 5);
		assertEquals(5, buf.length());
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Util#hex2bytes(java.lang.String)}.
	 */
	@Test
	void testHex2bytesNull() {
		assertNull(hex2bytes(null));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Util#hex2bytes(java.lang.String)}.
	 */
	@Test
	void testHex2bytesBadPattern() {
		assertThrows(IllegalArgumentException.class, () -> hex2bytes("01234567890abcdef"));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Util#bytes2hex(byte[])}.
	 */
	@Test
	void testBytes2hexNull() {
		assertNull(bytes2hex(null));
	}

	/**
	 * Test method for {@link it.pagopa.swclient.mil.idpay.authcode.Util#bytes2hex(byte[])}.
	 */
	@Test
	void testBytes2hexByteBelow0x10() {
		assertEquals("01", bytes2hex(new byte[] {
			1
		}));
	}
}
