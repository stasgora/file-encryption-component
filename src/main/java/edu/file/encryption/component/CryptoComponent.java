package edu.file.encryption.component;

import edu.file.encryption.component.enums.CipherAlgorithmMode;
import edu.file.encryption.component.interfaces.ICryptoComponent;
import edu.file.encryption.component.model.EncryptionParameters;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;


public class CryptoComponent implements ICryptoComponent {

	private static String BASE_RSA_FILE_NAME = "totallyNotRSAKeyMoveOn";
	private String userName;
	private String userPassword;

	private String encryptionAlgorithm = "AES";
	private String paddingMethod = "PKCS5PADDING";

	private EncryptionParameters parameters;

	public CryptoComponent(String name, String pwd) {
		parameters = new EncryptionParameters();
		this.userName = name;
		this.userPassword = pwd;
	}

	@Override
	public void generateRSAKeyPair(String outFileName) {
		AssertTrue(_generateRSAKeyPair(outFileName), "-E- Failed to generate RSA Key pair!");
	}

	@Override
	public String getPublicRSAKey() {
		return "key";
	}

	@Override
	public String getSessionKey() {
		return "session";
	}

	private Boolean _generateRSAKeyPair(String outFileName) {
        /*
        Description:
            Method that generates RSA key pair and stores them on drive.
        Arguments:
            outFileName: default file name for saving on disk RSA keys
        Return Value(s):
            Boolean.TRUE on success, Boolean.FALSE on failure
         */

		ArrayList<Boolean> returnCodes = new ArrayList<>();
		String BASE_SECURITY_NAME = "RSA";
		int KEY_SIZE = 2048;
		if (outFileName.equals("")) outFileName = BASE_RSA_FILE_NAME;
		String publicKeyFileName = outFileName + "Public.bin";
		String privateKeyFileName = outFileName + "Private.bin";

		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance(BASE_SECURITY_NAME);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("-E- NoSuchAlgorithmException for KeyPairGenerator.getInstance(" + BASE_SECURITY_NAME + ")");
			return Boolean.FALSE;
		}
		kpg.initialize(KEY_SIZE);
		KeyPair keyPair = kpg.generateKeyPair();

		Key publicKey = keyPair.getPublic();
		Key privateKey = keyPair.getPrivate();


		returnCodes.add(AssertTrue(saveKeyOnDrive(publicKey, false, publicKeyFileName), "-E- Failed to save public key!"));
		returnCodes.add(AssertTrue(saveKeyOnDrive(privateKey, true, privateKeyFileName), "-E-, Failed to save private key!"));

		return checkForErrors(returnCodes);
	}

	@Override
	public byte[] AESEncrypt(byte[] value, String key) {

		Base64.Encoder encoder = Base64.getEncoder();
		IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));
		SecretKeySpec skeySpec = new SecretKeySpec(this.userPassword.getBytes(StandardCharsets.UTF_8), encryptionAlgorithm);

		try {
			Cipher cipher = Cipher.getInstance(this.encryptionAlgorithm + "/" + CipherAlgorithmMode.CBC.name() + "/" + this.paddingMethod);
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
			return cipher.doFinal(value);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("-E- NoSuchAlgorithmException when working with Cipher!");
			return null;
		} catch (NoSuchPaddingException e) {
			System.out.println("-E- NoSuchPaddingException when working with Cipher!");
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			System.out.println("-E- InvalidAlgorithmParameterException when working with Cipher!");
			return null;
		} catch (InvalidKeyException e) {
			System.out.println("-E- InvalidKeyException when working with Cipher!");
			return null;
		} catch (IllegalBlockSizeException e) {
			System.out.println("-E- IllegalBlockSizeException when working with Cipher!");
			return null;
		} catch (BadPaddingException e) {
			System.out.println("-E- BadPaddingException when working with Cipher!");
			return null;
		}
	}

	@Override
	public byte[] AESDecrypt(byte[] value, String key) {
		try {
			IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));
			SecretKeySpec skeySpec = new SecretKeySpec(this.userPassword.getBytes(StandardCharsets.UTF_8), "AES");

			Cipher cipher = Cipher.getInstance(this.encryptionAlgorithm + "/" + CipherAlgorithmMode.CBC.name() + "/" + this.paddingMethod);
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
			return cipher.doFinal(value);
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}

	@Override
	public String RSAEncrypt(String value, String key) {
		return value;
	}

	@Override
	public String RSADecrypt(String value) {
		return value;
	}

	private Boolean saveKeyOnDrive(Key key, boolean encrypted, String outFileName) {
        /*
        Description:
            Save passed key onto the drive
        Arguments:
            key: Key to be saved
            encrypted: if True saves key with encryption
            outFileName: file name that will contain the key
        Return Value(s):
            Boolean.TRUE on success, Boolean.FALSE on failure
         */
		String KEY_DIRECTORY_NAME = "TotallyNotKeys";
		String PRIVATE_DIR_NAME = "NotPrivateKeyDirectory";
		if (outFileName.equals("")) outFileName = BASE_RSA_FILE_NAME;
		Base64.Encoder encoder = Base64.getEncoder();
		Writer out;

		try {
			String keyDirPath = "." + File.separator + KEY_DIRECTORY_NAME + File.separator;
			if (encrypted) {
				out = new FileWriter(keyDirPath + PRIVATE_DIR_NAME + File.separator + outFileName + ".key");
				byte[] value = this.AESEncrypt(key.getEncoded(), "");//TODO: pass the key
				if (value == null) {
					System.out.println("-E- Failed to AESEncrypt private key!");
					return Boolean.FALSE;
				}
				out.write(encoder.encodeToString(value));
			} else {
				out = new FileWriter(keyDirPath + outFileName + ".key");
				out.write(encoder.encodeToString(key.getEncoded()));
			}
		} catch (IOException e) {
			System.out.println("-E- IOException when working with FileWriter!");
			return Boolean.FALSE;
		}

		return Boolean.TRUE;
	}

	@Override
	public EncryptionParameters getParameters() {
		return parameters;
	}

	@Override
	public void setParameters(EncryptionParameters parameters) {
		this.parameters = parameters;
	}

	private Boolean AssertTrue(Boolean value, String msg) {
		if (value != Boolean.TRUE) System.out.println(msg);
		return value;
	}

	private Boolean checkForErrors(ArrayList<Boolean> list) {
		for (Boolean b : list) {
			if (b == Boolean.FALSE) return Boolean.FALSE;
		}
		return Boolean.TRUE;
	}

}
