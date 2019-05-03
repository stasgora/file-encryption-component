package edu.file.encryption.component.model;

import edu.file.encryption.component.enums.CipherAlgorithmMode;

public class EncryptionParameters {

	public String initialVector = "completelySecure";
	public String encryptionAlgorithm = "AES";
	public String paddingMethod = "PKCS5PADDING";

	public int RSA_keySize = 4096;
	public CipherAlgorithmMode cipherAlgMode;

	public String fileExtension;
	public String recipient;
	public int fileLength;

}
