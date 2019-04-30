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
import javax.sound.sampled.LineEvent;
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
	public void loginUser(String login, String pwd){
		this.userName = login;
		try{
			MessageDigest digest = MessageDigest.getInstance(this.hashFunctionName);
			byte[] encodedhash = digest.digest(pwd.getBytes(StandardCharsets.UTF_8));
			this.userPassword = new String(encodedhash);

		}catch(NoSuchAlgorithmException e){
			LOGGER.log(Level.SEVERE, "-E- Incorrect hash function name", e);
		}
		LOGGER.log(Level.WARNING, "-I- Proceeding to generate RSA");
		this.generateRSAKeyPair();
		this.generateSessionKey();
	}

	@Override
	public void generateRSAKeyPair() {
		AssertTrue(_generateRSAKeyPair(), "-E- Failed to generate RSA Key pair!");
	}

	@Override
	public String getPublicRSAKey() {
		String keyDirPath = String.join(File.separator,".", this.keyDir, this.userName);

		try {
			String publicRSAKey = new String(Files.readAllBytes(Paths.get(keyDirPath+this.publicKeySuffix)));
			return publicRSAKey;
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "-E- FileWriter IOException", e);
		}

		return "key"; // TODO HANDLE THIS CASE
	}

	@Override
	public String getPrivateRSAKey() {
		Base64.Encoder encoder = Base64.getEncoder();
		String keyDirPath = String.join(File.separator,".", this.keyDir, this.privateKeyDir,this.userName);

		try {
			byte[] privateEncryptedKey = Files.readAllBytes(Paths.get(keyDirPath+this.privateKeySuffix));
			byte[] value = this.AESDecrypt(privateEncryptedKey, this.userPassword, CipherAlgorithmMode.CBC);
			if (value == null) {
				LOGGER.log(Level.WARNING, "-W- Unable to decrypt private key");
			}
			return encoder.encodeToString(value);
		} catch (IOException e) {
			LOGGER.log(Level.WARNING, "-E- readAllBytes IOException", e);
		}
		return "key"; // TODO HANDLE THIS CASE
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
		IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));
		String cipherInstance = String.join("/", this.parameters.encryptionAlgorithm, cipherMode.name(), this.parameters.paddingMethod);

		try {
			Cipher cipher = Cipher.getInstance(cipherInstance);
			byte[] byteKey = key.getBytes();

			SecretKeySpec sKey = new SecretKeySpec(byteKey,0, 32, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, sKey, iv);
			return cipher.doFinal(value);
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
	public byte[] AESDecrypt(byte[] value, String key, CipherAlgorithmMode cipherMode) {
		try {
			IvParameterSpec iv = new IvParameterSpec(parameters.initialVector.getBytes(StandardCharsets.UTF_8));

			String cipherInstance = String.join("/", this.parameters.encryptionAlgorithm, cipherMode.name(), this.parameters.paddingMethod);
			Cipher cipher = Cipher.getInstance(cipherInstance);

			byte[] byteKey = key.getBytes();
			SecretKeySpec sKey = new SecretKeySpec(byteKey, 0, 32, "AES");
			cipher.init(Cipher.DECRYPT_MODE, sKey, iv);
			return cipher.doFinal(Base64.getDecoder().decode(value));
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

			byte[] pBytes = Base64.getDecoder().decode(key);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey pKey = keyFactory.generatePublic(keySpec);
			cipher.init(Cipher.ENCRYPT_MODE, pKey);

			int maxRSAblockLength = this.parameters.RSA_keySize / 8;

			byte[] encryptedBytes = new byte[((int)(value.getBytes().length / maxRSAblockLength)+1) * maxRSAblockLength];
			for(int i=0;i<value.getBytes().length;i+=maxRSAblockLength){
				String str = new String(value.getBytes(), i*maxRSAblockLength, Math.min(value.getBytes().length,maxRSAblockLength));
				byte[] bStr = cipher.doFinal(str.getBytes());
				System.arraycopy(bStr, 0, encryptedBytes, i*maxRSAblockLength, bStr.length);
			}
			String encryptedString = new String(encryptedBytes);
			return encryptedString;
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
		return "000"; // TODO: HANDLE THIS
	}

	@Override
	public String RSADecrypt(String value, String key) {

		try {
			Cipher cipher = Cipher.getInstance("RSA");

			byte[] pBytes = Base64.getDecoder().decode(key);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pBytes);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey pKey = keyFactory.generatePrivate(keySpec);
			cipher.init(Cipher.DECRYPT_MODE, pKey);
			LOGGER.log(Level.WARNING,"Decryption size: "+value.getBytes().length);

			int maxRSAblockLength = this.parameters.RSA_keySize / 8;
			int unprocessedLength = value.getBytes().length;
			LOGGER.log(Level.INFO, "maxRSABolckLength: "+ maxRSAblockLength);

			byte[] encryptedBytes = new byte[((int)(value.getBytes().length / maxRSAblockLength)+1) * maxRSAblockLength];
			for(int i=0;i<value.getBytes().length;i+=maxRSAblockLength){
				String str = new String(value.getBytes(), i*maxRSAblockLength, Math.min(unprocessedLength,maxRSAblockLength));
				LOGGER.log(Level.WARNING, "unprocessedLEngth: "+unprocessedLength);
				byte[] bStr = cipher.doFinal(str.getBytes());
				LOGGER.log(Level.WARNING, "bStr length: "+bStr.length);
				System.arraycopy(bStr, 0, encryptedBytes, i*maxRSAblockLength, bStr.length);
				unprocessedLength -= maxRSAblockLength;
			}
			String encryptedString = new String(encryptedBytes);
			return encryptedString;

		}catch(NoSuchAlgorithmException | NoSuchPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Wrong algorithm or padding", e);
		}catch(InvalidKeyException e){
			LOGGER.log(Level.WARNING, "-E- Invalid key during RSADecryption", e);
		}catch(IllegalBlockSizeException | BadPaddingException e){
			LOGGER.log(Level.WARNING, "-E- Illegal block size or bad padding during RSADecryption", e);
		}catch(InvalidKeySpecException e){
			LOGGER.log(Level.WARNING, "Invalid key spec in RSA Decrypt", e);
		}
		LOGGER.log(Level.WARNING, "-W- message failed decryption process");
		return "000"; // TODO: HANDLE THIS
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
				byte[] value = this.AESEncrypt(key.getEncoded(), this.userPassword, CipherAlgorithmMode.CBC);
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
