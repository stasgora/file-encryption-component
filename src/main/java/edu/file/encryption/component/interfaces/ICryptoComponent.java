package edu.file.encryption.component.interfaces;

import edu.file.encryption.component.enums.CipherAlgorithmMode;
import edu.file.encryption.component.model.EncryptionParameters;

public interface ICryptoComponent {

	void generateRSAKeyPair();

	void generateSessionKey();

	void loginUser(String login, String pwd);

	String getPublicRSAKey();

	String getPrivateRSAKey();

	String getSessionKey();

	byte[] AESEncrypt(byte[] value, String key, CipherAlgorithmMode cipherMode);

	byte[] AESDecrypt(byte[] value, String key, CipherAlgorithmMode cipherMode);

	byte[] RSAEncrypt(String value, String key);

	String RSADecrypt(byte[] value, String key);

	EncryptionParameters getParameters();

	void setParameters(EncryptionParameters parameters);

}
