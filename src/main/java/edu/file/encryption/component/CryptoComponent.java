package edu.file.encryption.component;

import edu.file.encryption.component.enums.CipherAlgorithmMode;
import edu.file.encryption.component.exceptions.NoRSAKeyFoundException;
import edu.file.encryption.component.exceptions.WrongKeyException;
import edu.file.encryption.component.interfaces.ICryptoComponent;
import edu.file.encryption.component.model.EncryptionParameters;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.sound.sampled.LineEvent;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;


public class CryptoComponent implements ICryptoComponent {
	private String userName;
	private String userPassword;
	private SecretKeySpec sessionKey;

	private String keyDir = "TotallyNotKeys";
	private String privateKeyDir = "NotPrivateKeyDirectory";
	private String publicKeySuffix = "Public.key";
	private String privateKeySuffix = "Private.key";
	private String hashFunctionName = "SHA-256";

	private EncryptionParameters parameters;
	private static final Logger LOGGER = Logger.getLogger(CryptoComponent.class.getName());

	public CryptoComponent() {
		parameters = new EncryptionParameters();
		this.generateSessionKey();
	}

	@Override
	public String getUserName(){
		return this.userName;
	}

	private Boolean checkForUserKeys(String login){
		String pubKeyDirPath = String.join(File.separator,".", this.keyDir,login);
		String privKeyDirPath = String.join(File.separator,".", this.keyDir, this.privateKeyDir,login);

		File pubKey = new File(pubKeyDirPath + this.publicKeySuffix);
		File privKey = new File(privKeyDirPath + this.privateKeySuffix);

		if(pubKey.exists() && privKey.exists()){
			return Boolean.TRUE;
		}
		return Boolean.FALSE;
	}

	@Override
	public void loginUser(String login, String pwd){
		this.userName = login;
		try{
			MessageDigest digest = MessageDigest.getInstance(this.hashFunctionName);
			byte[] encodedhash = digest.digest(pwd.getBytes(StandardCharsets.UTF_8));
			this.userPassword = Base64.getEncoder().encodeToString(encodedhash);

		}catch(NoSuchAlgorithmException e){
			LOGGER.log(Level.SEVERE, "-E- Incorrect hash function name", e);
		}

		if(checkForUserKeys(this.userName) == Boolean.FALSE){
			LOGGER.log(Level.INFO, "No keys for user, generating new ones");
			this.generateRSAKeyPair();
		}
		this.generateSessionKey();
	}

	@Override
	public void generateRSAKeyPair() {
		AssertTrue(_generateRSAKeyPair(), "-E- Failed to generate RSA Key pair!");
	}

	@Override
	public String getPublicRSAKey(String user) throws NoRSAKeyFoundException {
		Boolean userExist = checkForUserKeys(user);
		if(userExist == Boolean.FALSE){
			KeyPairGenerator kpg;
			try {
				kpg = KeyPairGenerator.getInstance("RSA");
			} catch (NoSuchAlgorithmException e) {
				LOGGER.log(Level.WARNING, "-E- No instance named RSA", e);
				return "";
			}
			kpg.initialize(this.parameters.RSA_keySize);
			KeyPair keyPair = kpg.generateKeyPair();
			Key publicKey = keyPair.getPublic();
			return Base64.getEncoder().encodeToString(publicKey.getEncoded());
		}
		String keyDirPath = String.join(File.separator,".", this.keyDir, user);

		try {
			String publicRSAKey = new String(Files.readAllBytes(Paths.get(keyDirPath+this.publicKeySuffix)));
			return publicRSAKey;
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "-E- FileWriter IOException", e);
		}
		throw new NoRSAKeyFoundException("Failed to get Public RSA key for user "+user);
	}

	@Override
	public String getPrivateRSAKey() throws NoRSAKeyFoundException, WrongKeyException {
		Base64.Encoder encoder = Base64.getEncoder();
		String keyDirPath = String.join(File.separator,".", this.keyDir, this.privateKeyDir,this.userName);

		try {
			byte[] privateEncryptedKey = Files.readAllBytes(Paths.get(keyDirPath+this.privateKeySuffix));
			String oldIV = this.parameters.initialVector;
			this.parameters.initialVector = "0123456789012345";
			byte[] value = this.AESDecrypt(privateEncryptedKey, this.userPassword, CipherAlgorithmMode.CBC);
			this.parameters.initialVector = oldIV;
			if (value == null) {
				LOGGER.log(Level.WARNING, "-W- Unable to decrypt private key");
			}
			return encoder.encodeToString(value);
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "-E- readAllBytes IOException", e);
		}catch(WrongKeyException e){
			throw new WrongKeyException("Wrong private key!");
		}
		throw new NoRSAKeyFoundException("Failed to get Private RSA key for user "+this.userName);
	}

	@Override
	public String getSessionKey() {
		return Base64.getEncoder().encodeToString(this.sessionKey.getEncoded());
	}

	@Override
	public void generateSessionKey(){
		try {
			MessageDigest digest = MessageDigest.getInstance(this.hashFunctionName);
			ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
			buffer.putLong(System.currentTimeMillis());
			byte[] encodedhash = digest.digest(buffer.array());
			LOGGER.log(Level.INFO, "-I- creating session key from time hash");
			this.sessionKey = new SecretKeySpec(encodedhash, 0 ,32, this.parameters.encryptionAlgorithm);
		}catch(NoSuchAlgorithmException e){
			LOGGER.log(Level.WARNING, "-W- Did not create hash for session key.");
		}
	}

	private Boolean _generateRSAKeyPair() {
        /*
        Description:
            Method that generates RSA key pair and stores them on drive.
        Arguments:
            outFileName: default file name for saving on disk RSA keys
        Return Value(s):
            Boolean.TRUE on success, Boolean.FALSE on failure
         */

		ArrayList<Boolean> returnCodes = new ArrayList<>();
		String publicKeyFileName = this.userName + this.publicKeySuffix;
		String privateKeyFileName = this.userName + this.privateKeySuffix;

		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.WARNING, "-E- No instance named RSA", e);
			return Boolean.FALSE;
		}
		long startTime = System.currentTimeMillis();
		kpg.initialize(this.parameters.RSA_keySize);
		KeyPair keyPair = kpg.generateKeyPair();

		long endTime = System.currentTimeMillis();
		LOGGER.log(Level.INFO, "RSA key pair generation in milliseconds: "+ (endTime - startTime));
		Key publicKey = keyPair.getPublic();
		Key privateKey = keyPair.getPrivate();


		returnCodes.add(AssertTrue(saveKeyOnDrive(publicKey, false, publicKeyFileName), "-E- Failed to save public key!"));
		returnCodes.add(AssertTrue(saveKeyOnDrive(privateKey, true, privateKeyFileName), "-E-, Failed to save private key!"));

		return checkForErrors(returnCodes);
	}

	@Override
	public byte[] AESEncrypt(byte[] value, String key, CipherAlgorithmMode cipherMode) {
		IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));
		String cipherInstance = String.join("/", this.parameters.encryptionAlgorithm, cipherMode.name(), this.parameters.paddingMethod);

		try {
			Cipher cipher = Cipher.getInstance(cipherInstance);
			byte[] byteKey = key.getBytes();

			SecretKeySpec sKey = new SecretKeySpec(byteKey,0, 32, "AES");
			if(cipherMode != CipherAlgorithmMode.ECB){
				cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);
			}else{
				cipher.init(Cipher.ENCRYPT_MODE, sKey);
			}
			long startTime = System.currentTimeMillis();
			byte[] result = cipher.doFinal(value);
			long endTime = System.currentTimeMillis();
			LOGGER.log(Level.INFO, "AES encryption of " + value.length +" bytes in milliseconds: "+ (endTime - startTime));
			return result;
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE, "-E- NoSuchAlgorithmException when working with Cipher!", e);
			return null;
		} catch (NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			LOGGER.log(Level.WARNING, "-E- Invalid Cipher parameters!", e);
			return null;
		} catch (InvalidKeyException e) {
			LOGGER.log(Level.WARNING, "-E- Invalid Key: "+key, e);
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
	public byte[] AESDecrypt(byte[] value, String key, CipherAlgorithmMode cipherMode) throws WrongKeyException {
		try {
			IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));

			String cipherInstance = String.join("/", this.parameters.encryptionAlgorithm, cipherMode.name(), this.parameters.paddingMethod);
			Cipher cipher = Cipher.getInstance(cipherInstance);

			byte[] byteKey = key.getBytes();
			SecretKeySpec sKey = new SecretKeySpec(byteKey, 0, 32, "AES");
			if(cipherMode != CipherAlgorithmMode.ECB){
				cipher.init(Cipher.DECRYPT_MODE, sKey, iv);
			}else{
				cipher.init(Cipher.DECRYPT_MODE, sKey);
			}
			if(value.length % 16 != 0){
				value = Base64.getDecoder().decode(value);
			}
			long startTime = System.currentTimeMillis();
			byte[] result = cipher.doFinal(value);
			long endTime = System.currentTimeMillis();
			LOGGER.log(Level.INFO, "AES decryption of " + value.length +" bytes in milliseconds: "+ (endTime - startTime));
			return result;
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE, "-E- NoSuchAlgorithmException when working with Cipher!", e);
			return null;
		} catch (NoSuchPaddingException | InvalidAlgorithmParameterException e) {
			LOGGER.log(Level.WARNING, "-E- Invalid Cipher parameters!", e);
			return null;
		} catch (InvalidKeyException e) {
			LOGGER.log(Level.WARNING, "-E- Invalid Key: "+key, e);
			return null;
		} catch (IllegalBlockSizeException e) {
			LOGGER.log(Level.WARNING, "-E- Illegal block size", e);
			return null;
		} catch (BadPaddingException e) {
			throw new WrongKeyException("Wrong key!");
		}
	}

	@Override
	public byte[] RSAEncrypt(String value, String key) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");

			byte[] pBytes = Base64.getDecoder().decode(key);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pKey = keyFactory.generatePublic(keySpec);
			cipher.init(Cipher.ENCRYPT_MODE, pKey);

			long startTime = System.currentTimeMillis();
			byte[] result = cipher.doFinal(value.getBytes());
			long endTime = System.currentTimeMillis();
			LOGGER.log(Level.INFO, "RSA encryption of " + value.getBytes().length +" bytes in milliseconds: "+ (endTime - startTime));
			return result;
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Wrong algorithm or padding", e);
		}catch(InvalidKeyException e){
			LOGGER.log(Level.WARNING, "-E- Invalid key during RSAEncryption", e);
		}catch(IllegalBlockSizeException | BadPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Illegal block size or bad padding during RSAEncryption", e);
		}catch(InvalidKeySpecException e){
			LOGGER.log(Level.WARNING, "Invalid key spec in RSA Encrypt", e);
		}
		LOGGER.log(Level.WARNING, "-W- message failed encryption process");
		return null; // TODO: HANDLE THIS
	}

	@Override
	public String RSADecrypt(byte[] value, String key) throws WrongKeyException {
		try {
			Cipher cipher = Cipher.getInstance("RSA");

			byte[] pBytes = Base64.getDecoder().decode(key);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey pKey = keyFactory.generatePrivate(keySpec);
			cipher.init(Cipher.DECRYPT_MODE, pKey);

			long startTime = System.currentTimeMillis();
			byte[] result = cipher.doFinal(value);
			long endTime = System.currentTimeMillis();
			LOGGER.log(Level.INFO, "RSA decryption of " + value.length +" bytes in milliseconds: "+ (endTime - startTime));
			return new String(result);

		}catch(NoSuchAlgorithmException | NoSuchPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Wrong algorithm or padding", e);
		}catch(InvalidKeyException e){
			LOGGER.log(Level.WARNING, "-E- Invalid key during RSADecryption", e);
		}catch(IllegalBlockSizeException e){
			LOGGER.log(Level.WARNING, "-E- Illegal block size", e);
		}catch(InvalidKeySpecException e){
			LOGGER.log(Level.WARNING, "Invalid key spec in RSA Decrypt", e);
		}catch(BadPaddingException e){
			throw new WrongKeyException("Wrong key!");
		}
		LOGGER.log(Level.WARNING, "-W- message failed decryption process");
		return Base64.getEncoder().encodeToString(value); // TODO: HANDLE THIS
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
		Base64.Encoder encoder = Base64.getEncoder();
		Writer out;

		try {
			String keyDirPath = "." + File.separator + this.keyDir + File.separator;
			if (encrypted) {
				LOGGER.log(Level.INFO, "-I- Checking for private Key localization");
				File file = new File(keyDirPath+ this.privateKeyDir + File.separator);
				if(!file.exists()){
					file.mkdirs();
					LOGGER.log(Level.INFO, "Created directory for private key");
				}
				out = new FileWriter(keyDirPath + this.privateKeyDir + File.separator + outFileName, false);
				// Saving secret key using AES with hash from user pwd as key
				String oldIV = this.parameters.initialVector;
				this.parameters.initialVector = "0123456789012345";
				byte[] value = this.AESEncrypt(key.getEncoded(), this.userPassword, CipherAlgorithmMode.CBC);
				this.parameters.initialVector = oldIV;
				if (value == null) {
					LOGGER.log(Level.WARNING, "-E- Failed to AESEncrypt private key!");
					return Boolean.FALSE;
				}
				out.write(encoder.encodeToString(value));
				out.close();
			} else {
				LOGGER.log(Level.INFO, "-I- Checking for public Key localization");
				File file = new File(keyDirPath);
				if(!file.exists()){
					file.mkdirs();
					LOGGER.log(Level.INFO, "Created directory for public key");
				}
				out = new FileWriter(keyDirPath + outFileName, false);
				out.write(encoder.encodeToString(key.getEncoded()));
				out.close();
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
