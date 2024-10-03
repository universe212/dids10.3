package org.example.zh;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class SequenceGenerator {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        byte[] seed = "my_seed".getBytes();
        int count = 10;
        
        // Generate the sequence
        List<byte[]> sequence = generateSequence256(seed, count);
        
        // Print the sequence
        for (int i = 0; i < sequence.size(); i++) {
            System.out.println(bytesToHex(sequence.get(i)));
        }
    }

    public static List<byte[]> generateSequence256(byte[] seed, int count) throws NoSuchAlgorithmException {
        List<byte[]> result = new ArrayList<>();
        byte[] current = seed;
        for (int i = 0; i < count; i++) {
            current = getHash(current);
            result.add(current);
        }
        return result;
    }

    public static byte[] getHash(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(input);
        return digest.digest();
    }

    // Helper method to convert byte array to hex string
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
