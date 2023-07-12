/*
 * AuthCodeBlockTest.java
 *
 * 6 lug 2023
 */
package it.pagopa.swclient.mil.idpay.authcode;

import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.decrypt;
import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.encrypt;
import static it.pagopa.swclient.mil.idpay.authcode.SecurityUtil.importSessionKey;
import static it.pagopa.swclient.mil.idpay.authcode.Util.hex2bytes;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.MockedStatic;

/**
 * 
 */
class AuthCodeBlockTest {
	/*
	 * 
	 */
	private static final long EUROCENTS = 12345;

	/*
	 * 
	 */
	private static final long EPOCH_MILLI = 1688634036799L;

	/*
	 * 
	 */
	private static final byte[] RND = hex2bytes("e1a1aa259d6c9218");

	/*
	 * 
	 */
	private static final byte[] SESSION_KEY_BYTES = hex2bytes("af801868b8abb6f6fe644da0c007216dfa6d089561d4a0f31b9256d65404f147");

	/*
	 * 
	 */
	private static final SecretKey SESSION_KEY = new SecretKeySpec(SESSION_KEY_BYTES, "AES");

	/*
	 * 
	 */
	private static RSAPublicKey PUBLIC_MASTER_KEY;
	static {
		try {
			PUBLIC_MASTER_KEY = (RSAPublicKey) KeyFactory.getInstance("RSA")
				.generatePublic(
					new X509EncodedKeySpec(
						hex2bytes("30820222300d06092a864886f70d01010105000382020f003082020a0282020100977895aded6bcec32e7fb844a92fe0e09c8615ab8914caa2a32f48777c781c536f88c52262a36f7d38d003c35046666899c621186f53b53ecdbbd6b7618b932157da3e183ba7c29c880af353564673209fb2e9921ee09ee6751372bdc406e50a201fd63b4d7bafad538e24f250d27764ff55c7ad513c003863d6d3e36c3f526f011fdf6af85f79d899eeae7d931eeb5c5d877dd0b5124a19c469df478b1ef378e4534b6da1f6ab19a8890f3d84b88f79e18a5ebddc837c80ca1dd3771ac3a062c2d2182bdca1b0ab13b2613492bbd211fb0ae9f0e9f44de5cfa5bd2fef1ae16f2de418dc3d90c091a1fecaff3aa81ab8f6626b223d5174985e451ab11ae6ed42312cdf5dd8e95eac2b6c21828a5c53b90f6e15d24ceb2a457efcce01f19f2dc801d13103b3c0cf3ba1032f6d13b8c35fe6db3f71259b4fcd1f4d537931a1ecfab05eb48676709fb658fcd4b27a86ab5108db49884868c50c37eff81166172663fae5978430b4dd5f8c38e9bd74810586a6e1552416d9aecee184c44d533f19f9ec3c1e276f43e0a68601a53f29f27176f5e96f2ae7a1e2cd2ea2a9a1b254799b66442ce9f394abbdad0780da04ec9d8bc7962347d4b38f7a5a926b1990adea75ac9cdcee0f70517284a3751192b5e378f43b4b8d5f6692095854bbad636fcc6957cb48937ec92cc0432370fab0d2ea62aff355a3d8b803bcd2473d0078817d250203010001")));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	/*
	 * 
	 */
	private static RSAPrivateKey PRIVATE_MASTER_KEY;
	static {
		try {
			PRIVATE_MASTER_KEY = (RSAPrivateKey) KeyFactory.getInstance("RSA")
				.generatePrivate(
					new PKCS8EncodedKeySpec(
						hex2bytes("30820942020100300d06092a864886f70d01010105000482092c308209280201000282020100977895aded6bcec32e7fb844a92fe0e09c8615ab8914caa2a32f48777c781c536f88c52262a36f7d38d003c35046666899c621186f53b53ecdbbd6b7618b932157da3e183ba7c29c880af353564673209fb2e9921ee09ee6751372bdc406e50a201fd63b4d7bafad538e24f250d27764ff55c7ad513c003863d6d3e36c3f526f011fdf6af85f79d899eeae7d931eeb5c5d877dd0b5124a19c469df478b1ef378e4534b6da1f6ab19a8890f3d84b88f79e18a5ebddc837c80ca1dd3771ac3a062c2d2182bdca1b0ab13b2613492bbd211fb0ae9f0e9f44de5cfa5bd2fef1ae16f2de418dc3d90c091a1fecaff3aa81ab8f6626b223d5174985e451ab11ae6ed42312cdf5dd8e95eac2b6c21828a5c53b90f6e15d24ceb2a457efcce01f19f2dc801d13103b3c0cf3ba1032f6d13b8c35fe6db3f71259b4fcd1f4d537931a1ecfab05eb48676709fb658fcd4b27a86ab5108db49884868c50c37eff81166172663fae5978430b4dd5f8c38e9bd74810586a6e1552416d9aecee184c44d533f19f9ec3c1e276f43e0a68601a53f29f27176f5e96f2ae7a1e2cd2ea2a9a1b254799b66442ce9f394abbdad0780da04ec9d8bc7962347d4b38f7a5a926b1990adea75ac9cdcee0f70517284a3751192b5e378f43b4b8d5f6692095854bbad636fcc6957cb48937ec92cc0432370fab0d2ea62aff355a3d8b803bcd2473d0078817d25020301000102820200070ee03bfd0d6227ed2c42bc0c52db51e1694c16df548a86b3ea444b066545bdf63b5e22ebe16814b7dcd58d632f0c9eeb7f747e577dae90911f4e1ce31ce6610e34c60cf4b1575baf93d70d21e98c26cfda3de65dada37f38a30c873431b562d8915de1b5e016bfbc5e2a1c3d2639830974dd50ec5bf53a00c8fb66f9b325010ad689df74586541f1c0fca78454a8aca2a7becb46b765f58d15f9335e690af903515af943abf8ad6c3c356b6d44f9068f106c0ec123980870f7f27e7679a4291b4bea98174d54d6a69c7ac96b86f8a876d56630f583394d5a9f83512452a680e5975f38855e8fe2995fae8f8b13ac946ed80786f9157e6f352c022ce62f2ee202df25de7769075c756588704105406af731b2bdbb674f36a5ba9923789d7257e9554495cddafb62d710abb235fe3dbb287c0d52fa4ec26c01dd17aa3eadcd34979871286e6d0c288b26f1c969c1142ba6e775cb210a95c528111564317749beab51bc3f59c43a147515712844de35fabf3173c264fab60e6ba35acb27c6aca1a0fd697a6800954d9bbf42b3dc9105504e69761bd0435e07b9e4261861c395f62fb3f017bd9f58bc85958a976c4b3ce44327e9abd72cf923fdcd89b618f064c437bdf9816e21a86b3c669f334d4c872f2d3a5ad73715b4a81f5d7fe045bef9c7c9562a52d8a2b197960cf77e3bbc9cd992f3272fa342d65f416f16542e0d57870282010100c76e0f8497ad08725d548ae752a1a531622cd80093a4bf8d43d3611c2d2b497ee405741257994eed35e1de5301202db9ec6805860234e6630f4768e30811eda4cd8d373d5f8899c5368225e8243265355f7ab70a6a2678adc618354b994e3d76b695162a2e4bf2a1f48f7318e55edc9daba87350603357c322cae82d2e0afd3190a09b9ec78a2a8768eccc4db5947e641a39c0e5c73830dd39a265bc7eb21d2c25e1ddfdeaf945aff2e0bc6f4e1287481af7e7c8d01d8cb433cacbadeac0b022014e2805800c8423ca3ae2d3e2859d769785c376cbf29e61a9da8e763c2620fbf4326e73dff91640af23f4b61f5471a5b19568da7c1436418671029ba3baa29f0282010100c26fe898b996315b25bc73b5996e78eac46f0f3ae732298f65af3a497264145874cf3224cedd473bd000e8b04e70a62f624f87f5fbac51e7e4dee7ce501eb64d247edac78d74d5c2b1fedf534be83978f17265b49bc3bb733be818d7871c4630b3b40f884f51064a7b3d06396c66e6010a2ed7318dd816eefd4472f27b07e67debe348c34b958e33ed4bbee76daba7b63c6e356122e277d994cdbed068f03100955598ed98282ffb1e40841851e4ed6239dafb266c655d0c0386f61dc94a10b5d8a4919c43a101c78a7bf0f5d19f677ee95b903323d756bdcbeed51dc1cab8e6dc8d7017be6d5172da216b2662736d47a9e76f65548d6c50e18a704608b16dbb0282010100aa42756f1ecaf40e274df9349a6034971f98e7643ea8857cc62e1d971f9cf82723e6dffc94dae6fe2f6541189e3a69af747c2e5305694253ca048e305d8068e1ad3765b4b8edf751de4268b872c6af8f4c8f88db945a79e6e9db5b0ccaba7850f479fdad4f4f39bb38fe8b25f314f4c68b79c9d112006369ce376ad6bf9b54244fb43e87e515394fd7ad6a92e176001dd821fc646f9bb263fc438015d8189a3d49ae36870467822e3fedcc123e9624f6d347589421d14881c441db7804963309251223aae672491201221aeb08564863a9e2e24876c010a5928c6bd9d76a39f8c0b79982c5f1732510216357651203e090e6dcd8c2dbc2a25873fce501786243028201004f491aebcc21b6969858b44644fe8b481039c958179698e3e46f03b19777bfe4221dab30df39d4264bb7532b319135f2f47fc1cd4887080f2b80c9bd936632a85a4d70211749a130f72c1b1cf84305cc8f883a78df5b7d408c1924a81e6c25230ee449c127b6be7df8aaf5b2ccc558dcebae160a1af116c8f575c7f9a0b9a3ff8d04ed52d5ab7285322a44fa51fa41354a87163539e8673ece32e7b04c5a45611b84000c4293809d41c4c518b5ac483059af35e28129043c35e3fed03e98791fedeb8d84ceff049ebd95b4b848765bd9a086b9d260b71aa3e258cd8688d3857a7e4d1e7c50267ba3fdd6cabea83eb13d1bc747e1660d1532160641aa0d396ca9028201006952181b079886257524e74041c980782d63b3741f9c18284bcc3bfbc0a61b38b6c63c265b7c245af222e7a56ed4e92795802ceff64121fc63e3d2e5ff9db3d5c1df6a30bff56baa8743d883c7a7c72ba50bcbf585b46c400dc575c515b40601245cf4412e327a89324a85efc6197e3d32fc5a94aebbd08489fae474a46268bbecdd6cd0a6c0238f09fa928f3b46fac48fc11b367b0d7c2f5bff0b9701b3d1d3e01ff08d5bcfc2f9a07a119957f14418025059e299c249eb1bf2054bec991194b303768042b300464321c13ef429498ba95a77adb828889eaa360f8e6cc57e2d2cafaba57919554c5be8ef29ff5caf83b549c9229d18d5c67cf74d1a5c587019")));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	/*
	 * 
	 */
	private static final String AUTH_CODE = "66778";

	/*
	 * 
	 */
	private static final String NIS = "990011223344";

	/*
	 * 
	 */
	private static final byte[] AUTH_CODE_BLOCK = hex2bytes("eab903ecae181dc09140ef5529ff4c57");

	/*
	 *
	 */
	private static byte[] ENC_SESSION_KEY;
	static {
		try {
			ENC_SESSION_KEY = encrypt(SESSION_KEY_BYTES, PUBLIC_MASTER_KEY);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	/*
	 * 
	 */
	private static final AuthCodeBlockData SEC_CODE_BLOCK_DATA = new AuthCodeBlockData(ENC_SESSION_KEY, AUTH_CODE_BLOCK);

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.AuthCodeBlock#getAuthCodeBlock(long, long, java.lang.String, java.lang.String, java.security.interfaces.RSAPublicKey)}.
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 */
	@Test
	void testGetAuthCodeBlock() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		try (
			MockedStatic<Validator> validator = mockStatic(Validator.class);
			MockedStatic<SecurityUtil> securityUtil = mockStatic(SecurityUtil.class);) {

			/*
			 * Mocking of Validator class.
			 */
			validator.when(() -> Validator.validateEpochMill(EPOCH_MILLI)).thenAnswer(Answers.RETURNS_SMART_NULLS);
			validator.when(() -> Validator.validateEurocents(anyLong())).thenCallRealMethod();
			validator.when(() -> Validator.validateNis(anyString())).thenCallRealMethod();
			validator.when(() -> Validator.validateAuthCode(anyString())).thenCallRealMethod();
			validator.when(() -> Validator.validateAuthCodeBlockData(any(AuthCodeBlockData.class))).thenCallRealMethod();
			validator.when(() -> Validator.validatePrivateKey(any(RSAPrivateKey.class))).thenCallRealMethod();
			validator.when(() -> Validator.validatePublicKey(any(RSAPublicKey.class))).thenCallRealMethod();

			/*
			 * Mocking of SecurityUtil.
			 */
			securityUtil.when(SecurityUtil::generateRnd).thenReturn(RND);
			securityUtil.when(SecurityUtil::generateSessionKey).thenReturn(SESSION_KEY);
			securityUtil.when(() -> SecurityUtil.encrypt(any(byte[].class), any(SecretKey.class), any(byte[].class))).thenCallRealMethod();
			securityUtil.when(() -> SecurityUtil.encrypt(any(byte[].class), any(RSAPublicKey.class))).thenCallRealMethod();
			securityUtil.when(() -> SecurityUtil.decrypt(any(byte[].class), any(SecretKey.class), any(byte[].class))).thenCallRealMethod();
			securityUtil.when(() -> SecurityUtil.decrypt(any(byte[].class), any(RSAPrivateKey.class))).thenCallRealMethod();
			securityUtil.when(() -> SecurityUtil.importSessionKey(any(byte[].class))).thenCallRealMethod();

			/*
			 * Test.
			 */
			AuthCodeBlockData secCodeBlockData = AuthCodeBlock.getAuthCodeBlock(EUROCENTS, EPOCH_MILLI, AUTH_CODE, NIS, PUBLIC_MASTER_KEY);

			SecretKey sessionKey = importSessionKey(decrypt(secCodeBlockData.getEncSessionKey(), PRIVATE_MASTER_KEY));
			assertEquals(SESSION_KEY, sessionKey);
			assertArrayEquals(AUTH_CODE_BLOCK, secCodeBlockData.getAuthCodeBlock());
		}
	}

	/**
	 * Test method for
	 * {@link it.pagopa.swclient.mil.idpay.authcode.AuthCodeBlock#getAuthCode(long, long, AuthCodeBlockData, String, RSAPrivateKey)}.
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 */
	@Test
	void testGetAuthCode() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		try (MockedStatic<Validator> validator = mockStatic(Validator.class)) {
			/*
			 * Mocking of Validator class.
			 */
			validator.when(() -> Validator.validateEpochMill(EPOCH_MILLI)).thenAnswer(Answers.RETURNS_SMART_NULLS);
			validator.when(() -> Validator.validateEurocents(anyLong())).thenCallRealMethod();
			validator.when(() -> Validator.validateNis(anyString())).thenCallRealMethod();
			validator.when(() -> Validator.validateAuthCode(anyString())).thenCallRealMethod();
			validator.when(() -> Validator.validateAuthCodeBlockData(any(AuthCodeBlockData.class))).thenCallRealMethod();
			validator.when(() -> Validator.validatePrivateKey(any(RSAPrivateKey.class))).thenCallRealMethod();
			validator.when(() -> Validator.validatePublicKey(any(RSAPublicKey.class))).thenCallRealMethod();

			/*
			 * Test.
			 */
			String authCode = AuthCodeBlock.getAuthCode(EUROCENTS, EPOCH_MILLI, SEC_CODE_BLOCK_DATA, NIS, PRIVATE_MASTER_KEY);
			assertEquals(AUTH_CODE, authCode);
		}
	}
}