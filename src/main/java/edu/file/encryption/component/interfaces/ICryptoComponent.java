package edu.file.encryption.component.interfaces;

import edu.file.encryption.component.model.EncryptionParameters;

public interface ICryptoComponent {

	void generateRSAKeyPair(String outFileName);

	void generateSessionKey();

	String getPublicRSAKey();

	String getSessionKey();

	byte[] AESEncrypt(byte[] value, String key);

	byte[] AESDecrypt(byte[] value, String key);

	String RSAEncrypt(String value, String key);

	String RSADecrypt(String value, String key);

	EncryptionParameters getParameters();

	void setParameters(EncryptionParameters parameters);

}
