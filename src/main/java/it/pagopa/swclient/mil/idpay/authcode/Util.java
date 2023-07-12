/*
 * Util.java
 *
 * 6 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import static java.lang.Math.min;

/**
 * 
 * @author Antonio Tarricone
 */
public class Util {
	/**
	 * 
	 */
	private Util() {
	}

	/**
	 * 
	 * @param buf
	 * @param filler
	 * @param len
	 */
	static void fix(StringBuilder buf, char filler, int len) {
		int n = buf.length();
		if (n > len) {
			buf.delete(len, n);
		} else if (n < len) {
			int m = len - n;
			for (int i = 0; i < m; i++) {
				buf.append(filler);
			}
		}
	}

	/**
	 * 
	 * @param a
	 * @param b
	 * @return
	 */
	static byte[] xor(byte[] a, byte[] b) {
		int n = min(a.length, b.length);
		byte[] c = new byte[n];
		for (int i = 0; i < n; i++) {
			c[i] = (byte) (a[i] ^ b[i]);
		}
		return c;
	}

	/**
	 * 
	 * @param hex
	 * @return
	 */
	static byte[] hex2bytes(String hex) {
		if (hex == null)
			return null;
		if (!hex.matches("^(\\p{XDigit}\\p{XDigit})*$"))
			throw new IllegalArgumentException("hex string must match ^(\\p{XDigit}\\p{XDigit})*$");
		byte[] bytes = new byte[hex.length() / 2];
		int i = 0;
		for (int j = 0; j < bytes.length; j++) {
			bytes[j] = (byte) Integer.valueOf(hex.substring(i, (i = i + 2)), 16).intValue();
		}
		return bytes;
	}

	/**
	 * 
	 * @param bytes
	 * @return
	 */
	static String bytes2hex(byte[] bytes) {
		if (bytes == null)
			return null;
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			int b = bytes[i];
			if (b < 0x00) {
				b = b + 0x100;
			}
			if (b < 0x10) {
				buf.append("0");
			}
			buf.append(Integer.toHexString(b));
		}
		return buf.toString();
	}
}