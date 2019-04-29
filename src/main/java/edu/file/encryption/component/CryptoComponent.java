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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


public class CryptoComponent implements ICryptoComponent {

	private static String BASE_RSA_FILE_NAME = "totallyNotRSAKeyMoveOn";
	private String userName;
	private String userPassword;
	private SecretKeySpec sessionKey;

	private EncryptionParameters parameters;
	private static final Logger LOGGER = Logger.getLogger(CryptoComponent.class.getName());

	public CryptoComponent(String name, String pwd) {
		parameters = new EncryptionParameters();
		this.userName = name;
		this.userPassword = pwd;
		this.generateSessionKey();
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
		return Base64.getEncoder().encodeToString(this.sessionKey.getEncoded());
	}

	@Override
	public void generateSessionKey(){
		ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(System.currentTimeMillis());
		SecretKeySpec skeySpec = new SecretKeySpec(buffer.array(), this.parameters.encryptionAlgorithm);
		this.sessionKey = skeySpec;
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
		if (outFileName.equals("")) outFileName = BASE_RSA_FILE_NAME;
		String publicKeyFileName = outFileName + "Public.bin";
		String privateKeyFileName = outFileName + "Private.bin";

		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance(this.parameters.RSA_name);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.WARNING, "-E- No instance named "+this.parameters.RSA_name, e);
			return Boolean.FALSE;
		}
		kpg.initialize(this.parameters.RSA_keySize);
		KeyPair keyPair = kpg.generateKeyPair();

		Key publicKey = keyPair.getPublic();
		Key privateKey = keyPair.getPrivate();


		returnCodes.add(AssertTrue(saveKeyOnDrive(publicKey, false, publicKeyFileName), "-E- Failed to save public key!"));
		returnCodes.add(AssertTrue(saveKeyOnDrive(privateKey, true, privateKeyFileName), "-E-, Failed to save private key!"));

		return checkForErrors(returnCodes);
	}

	@Override
	public byte[] AESEncrypt(byte[] value, String key, CipherAlgorithmMode cipherMode) {

		Base64.Encoder encoder = Base64.getEncoder();
		IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));
		//SecretKeySpec skeySpec = new SecretKeySpec(this.userPassword.getBytes(StandardCharsets.UTF_8), this.parameters.encryptionAlgorithm);
		String cipherInstance = String.join("/", this.parameters.encryptionAlgorithm, cipherMode.name(), this.parameters.paddingMethod);

		try {
			Cipher cipher = Cipher.getInstance(cipherInstance);
			cipher.init(Cipher.ENCRYPT_MODE, this.sessionKey, iv);
			return cipher.doFinal(value);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE, "-E- NoSuchAlgorithmException when working with Cipher!", e);
			return null;
		} catch (NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			LOGGER.log(Level.WARNING, "-E- Invalid Cipher parameters!", e);
			return null;
		} catch (InvalidKeyException e) {
			LOGGER.log(Level.WARNING, "-E- Invalid Key", e);
			return null;
		} catch (IllegalBlockSizeException e) {
			LOGGER.log(Level.WARNING, "-E- Illegal block size", e);
			return null;
		} catch (BadPaddingException e) {
			LOGGER.log(Level.WARNING, "-E- Bad padding", e);
			return null;
		}
	}

	@Override
	public byte[] AESDecrypt(byte[] value, String key, CipherAlgorithmMode cipherMode) {
		try {
			IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));
			//SecretKeySpec skeySpec = new SecretKeySpec(this.userPassword.getBytes(StandardCharsets.UTF_8), "AES");

			String cipherInstance = String.join("/", this.parameters.encryptionAlgorithm, cipherMode.name(), this.parameters.paddingMethod);
			Cipher cipher = Cipher.getInstance(cipherInstance);
			cipher.init(Cipher.DECRYPT_MODE, this.sessionKey, iv);
			return cipher.doFinal(value);
		} catch (Exception ex) {
			ex.printStackTrace();
			LOGGER.log(Level.WARNING, "-E- Failure when working with Cipher", ex);
		}
		return null;
	}

	@Override
	public String RSAEncrypt(String value, String key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");

			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8),"RSA");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			return new String(cipher.doFinal(value.getBytes()));
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Wrong algorithm or padding", e);
		}catch(InvalidKeyException e){
			LOGGER.log(Level.WARNING, "-E- Invalid key during RSAEncryption", e);
		}catch(IllegalBlockSizeException | BadPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Illegal block size or bad padding during RSAEncryption", e);
		}
		LOGGER.log(Level.WARNING, "-W- message failed encryption process");
		return value;
	}

	@Override
	public String RSADecrypt(String value, String key) {

		try {
			Cipher cipher = Cipher.getInstance("RSA");

			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8),"RSA");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			return new String(cipher.doFinal(value.getBytes()));
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Wrong algorithm or padding", e);
		}catch(InvalidKeyException e){
			LOGGER.log(Level.WARNING, "-E- Invalid key during RSADecryption", e);
		}catch(IllegalBlockSizeException | BadPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Illegal block size or bad padding during RSADecryption", e);
		}
		LOGGER.log(Level.WARNING, "-W- message failed decryption process");
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
				try {
					// Saving secret key using AES with hash from user pwd as key
					MessageDigest digest = MessageDigest.getInstance(this.parameters.hashFunctionName);
					byte[] encodedhash = digest.digest(this.userPassword.getBytes(StandardCharsets.UTF_8));
					byte[] value = this.AESEncrypt(key.getEncoded(), new String(encodedhash), this.parameters.cipherAlgMode.CBC);
					if (value == null) {
						System.out.println("-E- Failed to AESEncrypt private key!");
						return Boolean.FALSE;
					}
					out.write(encoder.encodeToString(value));
				}catch(NoSuchAlgorithmException e){
					LOGGER.log(Level.SEVERE, "-E- Incorrect hash function name", e);
				}
			} else {
				out = new FileWriter(keyDirPath + outFileName + ".key");
				out.write(encoder.encodeToString(key.getEncoded()));
			}
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "-E- FileWriter IOException", e);
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
