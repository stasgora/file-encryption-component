package edu.file.encryption.component;

public interface ICryptographicKey {
    void generateRSAKeyPair(String outFileName);
    String encrypt(String value);
    String decrypt(String value);
}
