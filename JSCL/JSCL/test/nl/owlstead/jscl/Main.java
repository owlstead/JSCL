package nl.owlstead.jscl;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.util.Arrays;

import nl.owlstead.jscl.bouncy.PKCS5S2_SHA256_ParametersGenerator;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.codehaus.jackson.Base64Variant;
import org.codehaus.jackson.Base64Variants;
import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.TextNode;

/**
 * Notes:
 * <ul>
 * <li>CCM bouncy default uses a tag size of 128 (using ParametersWithIV);</li>
 * <li>CCM bouncy is probably restricted to a single encrypt/decrypt (as the length must be known beforehand)</li>
 * <li>you need to strip the *last* 3 bytes off of the IV given by SJCL demo</li>
 * <li>no support for OCB2 (yet)</li>
 * <li>using LGPL code of Matthias G&auml;rtner for PBKDF2 as no direct support
 * for PBKDF2 in Java or Bouncy, and SHA256 support for PBE is missing entirely.
 * </li>
 * </ul>
 * 
 * 
 */
public final class Main {

    private static final Charset SJCL_CHARSET = Charset.forName("UTF-8");
    private static final int SJCL_IGNORED_TAIL_IV_BYTES = 3;
    private static final Base64Variant SJCL_BASE64 = new Base64Variant(
            Base64Variants.MIME_NO_LINEFEEDS, "SJCL", false, ' ', -1);

//    static {
//        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
//            Security.addProvider(new BouncyCastleProvider());
//        }
//    }

    // static {
    // final Provider prov =
    // Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
    // Set<Service> services = prov.getServices();
    // for (Service service : services) {
    // String algo = service.getAlgorithm();
    // if (algo.contains("PB")) {
    // System.out.println(algo);
    // }
    // }
    // }

    public static class PBEParameters {
        public byte[] salt;
        public int iterationCount;
        public int keySize;
    }

    // private static byte[] performPBKDF2(char[] password, Main.PBEParameters
    // p) throws GeneralSecurityException {
    // SecretKeyFactory pbeKDF2 =
    // SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    // PBEKeySpec keySpec = new PBEKeySpec(password, p.salt, p.iterationCount,
    // p.keySize);
    // SecretKey key = pbeKDF2.generateSecret(keySpec);
    // return key.getEncoded();
    // }

//    private static byte[] performPBKDF2(char[] password, Main.PBEParameters p)
//            throws GeneralSecurityException {
//        PBKDF2Parameters pbkdf2Parameters = new PBKDF2Parameters("HMACSHA256",
//                "UTF-8", p.salt, p.iterationCount);
//        // PRF prf = new MacBasedPRF("HMACSHA256");
//        PBKDF2 pbkdf2 = new PBKDF2Engine(pbkdf2Parameters);
//        return pbkdf2.deriveKey(new String(password), p.keySize / Byte.SIZE);
//    }

    private static byte[] decryptCCM(final org.bouncycastle.crypto.params.CCMParameters params,
            final byte[] data) throws InvalidCipherTextException {
        final BlockCipher bc = new AESFastEngine();
        final CCMBlockCipher ccm = new CCMBlockCipher(bc);
        ccm.init(false, params);
        final byte[] result = ccm.processPacket(data, 0, data.length);
        return result;
    }

    private static class SJCLCipherTextStruct implements CCMParameters, PBKDFParameters, CipherTextSource, AssociatedDataSource, SaltSource {
        byte[] iv;
        int v;
        int iter;
        int ks;
        int ts;
        String mode;
        byte[] adata;
        String cipher;
        byte[] salt;
        byte[] ct;
        
        @Override
        public byte[] getCipherText() {
            return ct;
        }
        
        @Override
        public byte[] getSalt() {
            return salt;
        }
        
        @Override
        public int getIterations() {
            return iter;
        }

        @Override
        public byte[] getNonce(int nonceSizeBytes) {
            return Arrays.copyOfRange(iv, 0, nonceSizeBytes);
        }
        
        @Override
        public int getTagSizeBits() {
            return ts;
        }

        @Override
        public int getKeySize() {
            return ks;
        }

        @Override
        public byte[] getAssociatedData() {
            return adata;
        }
        
        public int getVersion() {
            return v;
        }
    }
    
    private static SJCLCipherTextStruct readJsonCipherText(JsonNode rootNode) throws IOException {

        SJCLCipherTextStruct cipherText = new SJCLCipherTextStruct();

        // --- version ---
        cipherText.v = rootNode.path("v").asInt();
        if (cipherText.v != 1) {
            throw new IOException("Only version 1 supported");
        }

        // --- password related data ---
        TextNode saltNode = (TextNode) rootNode.path("salt");
        cipherText.salt = saltNode.getBinaryValue(SJCL_BASE64);
        cipherText.iter = rootNode.path("iter").asInt();
        cipherText.ks = rootNode.path("ks").asInt();

        // --- cipher related data ---
        cipherText.cipher = rootNode.path("cipher").asText();
        cipherText.mode = rootNode.path("mode").asText();

        if (!"AES".equalsIgnoreCase(cipherText.cipher)
                || !"CCM".equalsIgnoreCase(cipherText.mode)) {
            throw new IOException("Only AES/CCM supported");
        }

        cipherText.ts = rootNode.path("ts").asInt();

        // --- actual encrypted data ---

        TextNode ivNode = (TextNode) rootNode.path("iv");
        final byte[] fullIV = ivNode.getBinaryValue(SJCL_BASE64);
        cipherText.iv = Arrays.copyOfRange(fullIV, 0, fullIV.length
                - SJCL_IGNORED_TAIL_IV_BYTES);

        String adataText = URLDecoder.decode(rootNode.path("adata").asText(), "UTF-8");
        cipherText.adata = adataText.getBytes(SJCL_CHARSET);

        TextNode ctNode = (TextNode) rootNode.path("ct");
        cipherText.ct = ctNode.getBinaryValue(SJCL_BASE64);

        return cipherText;
    }
    

    /**
     * @param args
     */
    public static void main(String[] args) {
        
        String password = "test";

        final SJCLCipherTextStruct cipherText;
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode rootNode = mapper.readTree(new File("test2.json"));
            cipherText = readJsonCipherText(rootNode);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }

        try {

            final KeyParameter keyParam = performPBKDF2BouncyLW(cipherText.getSalt(), password.toCharArray(), cipherText);

            System.out.println(new String(Hex.encode(cipherText.getAssociatedData()),
                    SJCL_CHARSET));

            final org.bouncycastle.crypto.params.CCMParameters params =
                    new org.bouncycastle.crypto.params.CCMParameters(
                            keyParam, cipherText.ts, cipherText.iv, cipherText.adata);
            final byte[] pt2 = decryptCCM(params, cipherText.ct);
            final String pt2String = new String(pt2, SJCL_CHARSET);
            System.out.println(pt2String);

//        } catch (GeneralSecurityException e) {
//            throw new IllegalStateException(e);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException(e);
        }
    }


    private static KeyParameter performPBKDF2BouncyLW(byte[] salt, char[] charArray, PBKDFParameters p) {
        
        // S2 *is* PBKDF2, but the default used only HMAC(SHA-1)
        final PKCS5S2_SHA256_ParametersGenerator gen = new PKCS5S2_SHA256_ParametersGenerator();
        
        // lets not use String, as we cannot destroy strings, BC to the rescue!
        final byte[] pwBytes = Strings.toUTF8ByteArray(charArray);
        
        gen.init(pwBytes, salt, p.getIterations());
        final KeyParameter params = (KeyParameter) gen.generateDerivedMacParameters(p.getKeySize());
        
        // use for/next loop for older Java versions
        Arrays.fill(pwBytes, 0, pwBytes.length, (byte) 0);
        
        // returns the bytes within the key, so do not destroy key
        return params;
    }

}
