package edu.file.encryption.component.interfaces;

import edu.file.encryption.component.model.EncryptionParameters;

public interface ICryptoComponent {

	void generateRSAKeyPair(String outFileName);

	String getPublicRSAKey();

	String getSessionKey();

	String encryptAES(String value, String key);

	String decryptAES(String value, String key);

	String encryptRSA(String value, String key);

	String decryptRSA(String value);

	EncryptionParameters getParameters();

	void setParameters(EncryptionParameters parameters);

}
