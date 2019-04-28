package edu.file.encryption.component.model;

public class EncryptionParameters {

	public String initialVector = "completelySecure";
	public String encryptionAlgorithm = "AES";
	public String paddingMethod = "PKCS5PADDING";

	public String RSA_name = "RSA";
	public int RSA_keySize = 2048;

	public String hashFunctionName = "SHA-256";

	public String fileName;
	public int fileLength;

}
