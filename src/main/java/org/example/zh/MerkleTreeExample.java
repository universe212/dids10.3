package org.example.zh;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;



public class MerkleTreeExample {
    private static final int rBits = 160;
    private static final int qBits = 512;
    public static void main(String[] args) throws NoSuchAlgorithmException {
        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        PairingParameters params = pg.generate();
        Pairing pairing = PairingFactory.getPairing(params);
        String message = "hell";
        byte[] seed = "seed".getBytes();
        int count = 4;

        // Step 1: Split message into chunks
        List<String> chunks = Arrays.asList("h", "e", "l", "l");

        // Step 2: Generate salts and compute leaf hashes
        List<byte[]> salts = generateSequence256(seed, count);
        List<byte[]> leafHashes = new ArrayList<>();
        for (int i = 0; i < chunks.size(); i++) {
            byte[] combined = combine(chunks.get(i).getBytes(), salts.get(i));
            leafHashes.add(getHash(combined));
        }

        // Step 3: Compute Merkle root
        byte[] merkleRoot = computeMerkleRoot(leafHashes);

        // Step 4: Provide the verifier with necessary data
        byte[] firstChunkSalt = salts.get(0);
        List<byte[]> otherLeafHashes = leafHashes.subList(1, leafHashes.size());

        // Step 5: Verifier reconstructs the Merkle root
        byte[] firstChunkHash = getHash(combine(chunks.get(0).getBytes(), firstChunkSalt));
        byte[] reconstructedMerkleRoot = reconstructMerkleRoot(firstChunkHash, otherLeafHashes);

        Element hashedMerkleRoot1 = hashToG1(pairing, merkleRoot.toString()).getImmutable();
        Element hashedMerkleRoot12 = hashToG1(pairing, reconstructedMerkleRoot.toString()).getImmutable();
        // Verify if the reconstructed root matches the original root
        boolean isValid = Arrays.equals(merkleRoot, reconstructedMerkleRoot);
        System.out.println(merkleRoot.equals(reconstructedMerkleRoot));


        System.out.println("Merkle root valid: " + isValid);
    }

    private static List<byte[]> generateSequence256(byte[] seed, int count) throws NoSuchAlgorithmException {
        List<byte[]> result = new ArrayList<>();
        byte[] current = seed;
        for (int i = 0; i < count; i++) {
            current = getHash(current);
            result.add(current);
        }
        return result;
    }

    private static byte[] getHash(byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    private static byte[] combine(byte[] data, byte[] salt) {
        byte[] combined = new byte[data.length + salt.length];
        System.arraycopy(data, 0, combined, 0, data.length);
        System.arraycopy(salt, 0, combined, data.length, salt.length);
        return combined;
    }

    private static byte[] computeMerkleRoot(List<byte[]> leafHashes) throws NoSuchAlgorithmException {
        if (leafHashes.size() == 1) {
            return leafHashes.get(0);
        }
        List<byte[]> parentHashes = new ArrayList<>();
        for (int i = 0; i < leafHashes.size(); i += 2) {
            byte[] left = leafHashes.get(i);
            byte[] right = (i + 1 < leafHashes.size()) ? leafHashes.get(i + 1) : left;
            parentHashes.add(getHash(combine(left, right)));
        }
        return computeMerkleRoot(parentHashes);
    }

    private static byte[] reconstructMerkleRoot(byte[] firstLeafHash, List<byte[]> otherLeafHashes) throws NoSuchAlgorithmException {
        List<byte[]> allLeafHashes = new ArrayList<>();
        allLeafHashes.add(firstLeafHash);
        allLeafHashes.addAll(otherLeafHashes);
        return computeMerkleRoot(allLeafHashes);
    }
    private static Element hashToG1(Pairing pairing, String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes());
        Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        return h;
    }
}
