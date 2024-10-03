package org.example.zh;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class UDVSExample {

    private static final int rBits = 160;
    private static final int qBits = 512;
    private static final int CHUNK_SIZE = 4; // Adjust chunk size as needed

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // Step 1: Setup the pairing
        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        PairingParameters params = pg.generate();
        Pairing pairing = PairingFactory.getPairing(params);

        // Step 2: Generate issuer's private key and public key
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element issuerPrivateKey = pairing.getZr().newRandomElement().getImmutable();
        Element issuerPublicKey = g.powZn(issuerPrivateKey).getImmutable();

        // Step 3: Generate designated verifier's private key and public key
        Element verifierPrivateKey = pairing.getZr().newRandomElement().getImmutable();
        Element verifierPublicKey = g.powZn(verifierPrivateKey).getImmutable();

        // Step 4: Hash the message chunks to points in G1 and create Merkle tree
        String message = "hell";
        List<String> chunks = splitMessageIntoChunks(message, CHUNK_SIZE);
        List<Element> leafNodes = new ArrayList<>();
        for (String chunk : chunks) {
            byte[] seed = chunk.getBytes();
            List<byte[]> sequence = generateSequence256(seed, 10); // Generate a sequence of 10 hashes
            for (byte[] seqHash : sequence) {
                leafNodes.add(hashToG1(pairing, seqHash).getImmutable());
            }
        }
        Element merkleRoot = computeMerkleRoot(pairing, leafNodes);

        // Step 5: Hash the Merkle root
        Element hashedMerkleRoot = hashToG1(pairing, merkleRoot.toString()).getImmutable();

        // Step 6: Issuer signs the hashed Merkle root
        Element issuerSignature = hashedMerkleRoot.powZn(issuerPrivateKey).getImmutable();

        // Step 7: Convert the signature using the verifier's public key
        Element transformedSignature = pairing.pairing(issuerSignature, verifierPublicKey).getImmutable();



        // Step 8: Verifier verifies the signature
        Element verifierSignature = hashedMerkleRoot.powZn(verifierPrivateKey).getImmutable();
        Element expectedPairing = pairing.pairing(verifierSignature, issuerPublicKey).getImmutable();

        boolean isValid = transformedSignature.isEqual(expectedPairing);
        System.out.println("Signature valid: " + isValid);
    }

    private static Element hashToG1(Pairing pairing, String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes());
        Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        return h;
    }

    private static Element hashToG1(Pairing pairing, byte[] input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(input);
        Element h = pairing.getG1().newElementFromHash(hash, 0, hash.length);
        return h;
    }

    private static List<String> splitMessageIntoChunks(String message, int chunkSize) {
        List<String> chunks = new ArrayList<>();
        int length = message.length();
        for (int i = 0; i < length; i += chunkSize) {
            chunks.add(message.substring(i, Math.min(length, i + chunkSize)));
        }
        return chunks;
    }

    /**
     * 计算默克尔根
     * @param pairing
     * @param leaves
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static Element computeMerkleRoot(Pairing pairing, List<Element> leaves) throws NoSuchAlgorithmException {
        if (leaves.size() == 1) {
            return leaves.get(0);
        }
        List<Element> parents = new ArrayList<>();
        for (int i = 0; i < leaves.size(); i += 2) {
            if (i + 1 < leaves.size()) {
                Element left = leaves.get(i);
                Element right = leaves.get(i + 1);
                parents.add(hashToG1(pairing, left.toString() + right.toString()).getImmutable());
            } else {
                parents.add(leaves.get(i));
            }
        }
        return computeMerkleRoot(pairing, parents);
    }

    /**
     * 生成序列
     * @param seed
     * @param count
     * @return
     * @throws NoSuchAlgorithmException
     */
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
        digest.update(input);
        return digest.digest();
    }
}
