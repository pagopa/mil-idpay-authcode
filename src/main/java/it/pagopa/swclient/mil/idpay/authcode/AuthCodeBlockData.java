/*
 * AuthCodeBlockData.java
 *
 * 6 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import lombok.Getter;

/**
 * 
 * @author Antonio Tarricone
 */
@Getter
public class AuthCodeBlockData {
	/*
	 * 
	 */
	private byte[] encSessionKey;

	/*
	 * 
	 */
	private byte[] authCodeBlock;

	/**
	 * 
	 * @param encSessionKey
	 * @param authCodeBlock
	 */
	public AuthCodeBlockData(byte[] encSessionKey, byte[] authCodeBlock) {
		this.encSessionKey = encSessionKey;
		this.authCodeBlock = authCodeBlock;
		validate();
	}

	/**
	 * 
	 */
	public void validate() {
		if (authCodeBlock == null)
			throw new IllegalArgumentException("authCodeBlock must not be null");
		if (authCodeBlock.length != 16)
			throw new IllegalArgumentException("authCodeBlock length must be 16");
		if (encSessionKey == null)
			throw new IllegalArgumentException("encSessionKey must not be null");
	}
}