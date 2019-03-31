package edu.file.encryption.component;

import edu.file.encryption.component.model.EncryptionParameters;

public interface ICryptographicKey {

	void generateRSAKeyPair(String outFileName);

	String encrypt(String value, String key);

	String decrypt(String value, String key);

	EncryptionParameters getParameters();

	void setParameters(EncryptionParameters parameters);

}
