package edu.file.encryption.component.model;

import edu.file.encryption.component.enums.CipherAlgorithmMode;

public class EncryptionParameters {

	public String initialVector = "completelySecure";
	public String encryptionAlgorithm = "AES";
	public String paddingMethod = "PKCS5PADDING";

	public String RSA_name = "RSA";
	public int RSA_keySize = 2048;

	public CipherAlgorithmMode cipherAlgMode;
	public String hashFunctionName = "SHA-256";

	public String keyDir = "TotallyNotKeys";
	public String privateKeyDir = "NotPrivateKeyDirectory";
	public String publicKeySuffix = "Public.key";
	public String privateKeySuffix = "Private.key";
	public String fileName;
	public int fileLength;

}
