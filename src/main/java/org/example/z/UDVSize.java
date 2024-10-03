package org.example.z;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * ClassName: UDVSize
 * Package: org.example.z
 * Description
 *
 * @Author HuanZ
 * @Create 2024/7/14 15:32
 * @Version 1.0
 */

/**
 * 最终实验
 */
public class UDVSize {

    private static final int rBits = 160;
    private static final int qBits = 512;
    private static final int CHUNK_SIZE = 1; // Each character in "hell" is treated as a chunk

    public static void main(String[] args) throws NoSuchAlgorithmException {
        /**
         * 系统初始化
         */

        long startTime = System.currentTimeMillis();
// 执行你的代码


        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        PairingParameters params = pg.generate();
        Pairing pairing = PairingFactory.getPairing(params);
        long endTime = System.currentTimeMillis();
        long duration = endTime - startTime;
        System.out.println("系统初始化执行时间（毫秒）: " + duration);



        /**
         * 密钥生成
         */
        long startTime2 = System.currentTimeMillis();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element issuerPrivateKey = pairing.getZr().newRandomElement().getImmutable();
        Element issuerPublicKey = g.powZn(issuerPrivateKey).getImmutable();

        Element holderPrivateKey = pairing.getZr().newRandomElement().getImmutable();
        Element holderPublicKey = g.powZn(holderPrivateKey).getImmutable();

        Element verifierPrivateKey = pairing.getZr().newRandomElement().getImmutable();
        Element verifierPublicKey = g.powZn(verifierPrivateKey).getImmutable();

        long endTime2 = System.currentTimeMillis();
        long duration2 = endTime2 - startTime2;
        System.out.println("密钥生成执行时间（毫秒）: " + duration2);

        /**
         * 服务器颁发VC
         */
        long startTime3 = System.currentTimeMillis();
        byte[] seed = "seed".getBytes();
        int count = 4;
        // Step 1: Split message into chunks
        List<String> chunks = Arrays.asList("温度采集", "设备ID5215421563", "设备名称", "asasdasdasdsaddasd");
        int totalBits = 0;
        for (String chunk : chunks) {
            byte[] bytes = chunk.getBytes(); // 默认使用UTF-8编码
            totalBits += bytes.length * 8; // 计算每个字符串的比特数
        }

        System.out.println("Total bits: " + totalBits);
        List<byte[]> salts = generateSequence256(seed, count);
        List<byte[]> leafHashes = new ArrayList<>();
        for (int i = 0; i < chunks.size(); i++) {
            byte[] combined = combine(chunks.get(i).getBytes(), salts.get(i));
            leafHashes.add(getHash(combined));
        }

        // 计算默克尔根
        byte[] merkleRoot = computeMerkleRoot(leafHashes);

        // hash默克尔根
        Element hashedMerkleRoot = hashToG1(pairing, merkleRoot).getImmutable();

        // 对默克尔根签名
        Element issuerSignatureMerkleRoot = hashedMerkleRoot.powZn(issuerPrivateKey).getImmutable();

        //生成vc
        //String chineseInfo = "DID文档";
        String chineseInfo = "@context\": [\n" +
                "    \"https://www.w3.org/2018/credentials/v1\",\n" +
                "    \"https://www.w3.org/2018/credentials/examples/v1\"\n" +
                "  ],\n" +
                "  // 本VC的唯一标识，也就是证书ID\n" +
                "  \"id\": \"uestc/alumni/12345\",\n" +
                "  // VC内容的格式\n" +
                "  \"type\": [\"VerifiableCredential\", \"AlumniCredential\"],\n" +
                "  // 本VC的发行人\n" +
                "  \"issuer\": \"did:cedu:uestc\",\n" +
                "  // 本VC的发行时间\n" +
                "  \"issuanceDate\": \"2010-07-01T19:73:24Z\",\n" +
                "  // VC声明的具体内容\n" +
                "  \"credentialSubject\": {\n" +
                "    // 被声明的人的DID\n" +
                "    \"id\": \"did:cid:511112200001010015\",\n" +
                "    // 声明内容:毕业院校、专业、学位等\n" +
                "    \"name\":\"小明\",\n" +
                "    \"alumniOf\": {\n" +
                "      \"id\": \"did:cedu:uestc\",\n" +
                "      \"name\": [{\n" +
                "        \"value\": \"电子科技大学\",\n" +
                "        \"lang\": \"cn\"\n" +
                "      }]\n" +
                "    },\n" +
                "    \"degree\":\"硕士研究生\",\n" +
                "    \"degreeType\":\"工科\",\n" +
                "    \"college\":\"计算机学院\"\n" +
                "  },\n" +
                "  // 对本VC的证明\n" +
                "  \"proof\": {\n" +
                "    \"creator\": \"did:cedu:uestc#keys-1\",\n" +
                "    \"type\": \"Secp256k1\",\n" +
                "    \"signatureValue\": \"3044022051757c2de7032a0c887c3fcef02ca3812fede7ca748254771b9513d8e2bb\"";
        byte[] chineseInfoBytes = chineseInfo.getBytes(StandardCharsets.UTF_8);
        // 对于G1、G2等群元素，使用toBytes方法
        byte[] merkleroot = issuerSignatureMerkleRoot.toBytes();

        byte[] vc = new byte[merkleroot.length + chineseInfoBytes.length];
        System.arraycopy(merkleroot, 0, vc, 0, merkleroot.length);
        System.arraycopy(chineseInfoBytes, 0, vc, merkleroot.length, chineseInfoBytes.length);
        //生成VP

        // hash vc
        Element hashVcSignature = hashToG1(pairing, vc).getImmutable();

        // 签名Vc
        Element issuerSignatureVP = hashVcSignature.powZn(issuerPrivateKey).getImmutable();

        long endTime3 = System.currentTimeMillis();
        long duration3 = endTime3 - startTime3;
        System.out.println("颁发VP执行时间（毫秒）: " + duration3);


        /**
         * 持有者验证VC签名
         */
        long startTime33 = System.currentTimeMillis();

        Element vcHash = hashToG1(pairing, vc).getImmutable();

        Element expectedPairing0 = pairing.pairing(issuerSignatureVP, g).getImmutable();
        Element expectedPairing00 = pairing.pairing(vcHash, issuerPublicKey).getImmutable();
        boolean isValid11 = expectedPairing00.isEqual(expectedPairing0);
        System.out.println("验证签名结果"+isValid11);

        long endTime33 = System.currentTimeMillis();
        long duration33 = endTime33 - startTime33;


        //模拟添加VP

        String chineseInfo1 = " \"@context\": [\n" +
                "    \"https://www.w3.org/2018/credentials/v1\",\n" +
                "    \"https://studyzyexamples.com/identity/v1\"\n" +
                "  ],\n" +
                "  \"type\": \"VerifiablePresentation\",\n" +
                "  // 本VP包含的VC的内容\n" +
                "  \"verifiableCredential\": [{\n" +
                "    \"@context\": [\n" +
                "    \"https://www.w3.org/2018/credentials/v1\",\n" +
                "    \"https://studyzyexamples.com/identity/v1\"\n" +
                "  ],\n" +
                "  \"id\": \"vc511112200001010015\",\n" +
                "  \"type\": [\"VerifiableCredential\", \"Identity\"],\n" +
                "  \"issuer\": \"did:公安部门ID\",\n" +
                "  \"issuanceDate\": \"2010-07-01T19:73:24Z\",\n" +
                "  \"credentialSubject\": {\n" +
                "    \"id\": \"did:cid:511112200001010015\",\n" +
                "    //以下是要选择性披露的内容\n" +
                "    \"birthdate\":\"2000-01-01\",\n" +
                "    //以下是验证披露字段有效性的数据\n" +
                "    //数据在默克尔树中的索引\n" +
                "    \"dataIndex\":2,\n" +
                "    //本数据加盐的值\n" +
                "    \"salt\":\"6b264354ed367ced527a86d38f75f9c3888bd3939f548cc48d93af435890b84a\",\n" +
                "    //默克尔验证路径\n" +
                "    \"merklesibling\":\"34b64151443c3124620bf4ff69a05e97d580f0878b374b8343c6a5c3d8223435 9d2b5b35ccb5bf18747c1f5dc05771c68ce613e6eb0c5f5ef77cec8ba3e9da67 bb82c63d4e21525125bf66a6724fbb4dcbded26aae2baa2633235dc12730016e\",\n" +
                "    //默克尔根哈希\n" +
                "    \"merkleRoot\":\"ea59a369466be42d1a4783f09ae0721a5a157d6dba9c4b053d407b5a4b9af145\",\n" +
                "    //公安机关对默克尔根的签名\n" +
                "    \"rootSignature\":\"3066022051757c2de7032a0c887c3fcef02ca3812fede7ca748254771b9513d8e266\",\n" +
                "    //用的公安机关哪个Key进行的签名\n" +
                "    \"signer\":\"did:公安部门ID#keys-1\"\n" +
                "  },\n" +
                "  \n" +
                "  }],\n" +
                "  // Holder小明对本VP的签名信息\n" +
                "  \"proof\": {\n" +
                "    \"type\": \"Secp256k1\",\n" +
                "    \"created\": \"2010-07-02T21:19:10Z\",\n" +
                "    \"proofPurpose\": \"authentication\",\n" +
                "    \"verificationMethod\": \"did:cid:511112200001010015#keys-1\",\n" +
                "    // challenge和domain是为了防止重放攻击而设计的\n" +
                "    \"challenge\": \"1f44d55f-f161-4938-a659-f8026467f126\",\n" +
                "    \"domain\": \"4jt78h47fh47\",\n" +
                "    \"jws\": \"eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..kTCYt5\n" +
                "      XsITJX1CxPCT8yAV-TVIw5WEuts01mq-pQy7UJiN5mgREEMGlv50aqzpqh4Qq_PbChOMqs\n" +
                "      LfRoPsnsgxD-WUcX16dUOqV0G_zS245-kronKb78cPktb3rk-BuQy72IFLN25DYuNzVBAh\n" +
                "      4vGHSrQyHUGlcTwLtjPAnKb78\"\n" +
                "  }";
        byte[] chineseInfoBytesvp = chineseInfo1.getBytes(StandardCharsets.UTF_8);

        byte[] vp = new byte[chineseInfoBytesvp.length];



        System.out.println("验证签名执行时间（毫秒）: " + duration33);



        /**
         * 持有者转换签名
         */
        //step3 持有者转换签名
        long startTime4 = System.currentTimeMillis();

        //对服务器的默克尔根签名进行转换
        Element transformedSignature = pairing.pairing(issuerSignatureMerkleRoot, verifierPublicKey).getImmutable();


        //对生成的vp进行签名
        Element issuerSignatureVP1 = hashVcSignature.powZn(holderPrivateKey).getImmutable();
        //对vp进行转换
        Element transformedSignature1 = pairing.pairing(issuerSignatureVP1, verifierPublicKey).getImmutable();

        long endTime4 = System.currentTimeMillis();
        long duration4 = endTime4 - startTime4;
        System.out.println("生成VP转换签名执行时间（毫秒）: " + duration4);



        /**
         * 认证网关验证转换签名
         */
        //获取叶子节点和对应的序列号
        byte[] firstChunkSalt = salts.get(0);
        List<byte[]> otherLeafHashes = leafHashes.subList(1, leafHashes.size());


        // Step 4:认证网关验签
        long startTime5 = System.currentTimeMillis();


        // 把叶子节点和序列号结合
        byte[] firstChunkHash = getHash(combine(chunks.get(0).getBytes(), firstChunkSalt));


        //重构默克尔树
        byte[] reconstructedMerkleRoot = reconstructMerkleRoot(firstChunkHash, otherLeafHashes);



        //计算重新构造默克尔树hash值
        Element hashedMerkleRoot11 = hashToG1(pairing, reconstructedMerkleRoot).getImmutable();

        //认证网关对vc哈希
        Element vcSignature11 = hashToG1(pairing, vc).getImmutable();
        //认证网关原来信息用私钥进行签名  h^x 签名
        Element verifierSignature1 = vcSignature11.powZn(verifierPrivateKey).getImmutable();
        Element verifierSignature = hashedMerkleRoot11.powZn(verifierPrivateKey).getImmutable();


        //认证网关生成 转换签名对应的表达式 e(签名,公钥)
        Element expectedPairing1 = pairing.pairing(verifierSignature1, holderPublicKey).getImmutable();
        Element expectedPairing = pairing.pairing(verifierSignature, issuerPublicKey).getImmutable();



        //验证是否相等
        boolean isValid1 = transformedSignature1.isEqual(expectedPairing1);
        boolean isValid = transformedSignature.isEqual(expectedPairing);
        long endTime5 = System.currentTimeMillis();
        long duration5 = endTime5 - startTime5;
        System.out.println("验证VP执行时间（毫秒）: " + duration5);
        System.out.println("转换签名默克尔根 valid: " + isValid);
        System.out.println("转换签名VP validvp: " + isValid1);

        // Calculate and print communication costs
        calculateCommunicationCosts(leafHashes, merkleroot, chineseInfoBytes, vc, vp);
    }

    private static void calculateCommunicationCosts(List<byte[]> leafHashes, byte[] merkleroot, byte[] chineseInfoBytes, byte[] vc, byte[] vp) {
        int leafHashesSize = leafHashes.stream().mapToInt(hash -> hash.length).sum();
        int merkleRootSize = merkleroot.length;
        int chineseInfoSize = chineseInfoBytes.length;
        int vcSize = vc.length;
        int vpSize = vp.length;

        int totalSize = leafHashesSize + merkleRootSize + chineseInfoSize + vcSize + vpSize;

        System.out.println("叶子节点哈希总大小（字节）: " + leafHashesSize);
        System.out.println("默克尔根大小（字节）: " + merkleRootSize);
        System.out.println("VC内容大小（字节）: " + chineseInfoSize);
        System.out.println("VC总大小（字节）: " + vcSize);
        System.out.println("VP总大小（字节）: " + vpSize);
        System.out.println("通信总开销（字节）: " + totalSize);
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

    private static byte[] combine(byte[] data, byte[] salt) {
        byte[] combined = new byte[data.length + salt.length];
        System.arraycopy(data, 0, combined, 0, data.length);
        System.arraycopy(salt, 0, combined, data.length, salt.length);
        return combined;
    }

    private static byte[] reconstructMerkleRoot(byte[] firstLeafHash, List<byte[]> otherLeafHashes) throws NoSuchAlgorithmException {
        List<byte[]> allLeafHashes = new ArrayList<>();
        allLeafHashes.add(firstLeafHash);
        allLeafHashes.addAll(otherLeafHashes);
        return computeMerkleRoot(allLeafHashes);
    }
}
