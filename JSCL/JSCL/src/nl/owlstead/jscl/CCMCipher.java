package nl.owlstead.jscl;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class CCMCipher {

    private static final boolean MODE_ENCRYPT = true;  
    private static final boolean MODE_DECRYPT = false;  
    
    private enum State {
        INSTANTIATED,
        INITIALIZED,
        ;
    }
    
    private final CCMBlockCipher ccm;
    private CCMParameters params;
    private KeyParameter key;
    private State state;
    
    public CCMCipher() {
        final BlockCipher bc = new AESFastEngine();
        ccm = new CCMBlockCipher(bc);
        state = State.INSTANTIATED;
    }
    
    void init(final KeyParameter key, final CCMParameters params) {
        this.key = key;
        this.params = params;
        state = State.INITIALIZED;
    }
    
    byte[] encrypt(final byte[] associatedData, final byte[] plain) {
        if (state != State.INITIALIZED) {
            throw new IllegalStateException("CCMCipher not initialized");
        }
        
        final int nonceSizeBytes = 13;
        org.bouncycastle.crypto.params.CCMParameters bcParams =
                new org.bouncycastle.crypto.params.CCMParameters(
                        key, params.getTagSizeBits(), params.getNonce(nonceSizeBytes), associatedData);
        ccm.init(MODE_ENCRYPT, bcParams);
        byte[] result;
        try {
            result = ccm.processPacket(plain, 0, plain.length);
//        } catch (IllegalStateException e) {
//            throw new InvalidTagException(e);
        } catch (InvalidCipherTextException e) {
            throw new IllegalStateException("Plain text should not have restrictions");
        }
        return result;
    }
    
    byte[] decrypt(final byte[] associatedData, final byte[] cipherText) throws InvalidTagException {
        if (state != State.INITIALIZED) {
            throw new IllegalStateException("CCMCipher not initialized");
        }
        
        // TODO calculate nonceSizeBytes from cipherText size
        final int nonceSizeBytes = 13;
        org.bouncycastle.crypto.params.CCMParameters bcParams =
                new org.bouncycastle.crypto.params.CCMParameters(
                        key, params.getTagSizeBits(), params.getNonce(nonceSizeBytes), associatedData);
        ccm.init(MODE_DECRYPT, bcParams);
        byte[] result;
        try {
            result = ccm.processPacket(cipherText, 0, cipherText.length);
//        } catch (IllegalStateException e) {
//            throw new InvalidTagException(e);
        } catch (InvalidCipherTextException e) {
            throw new InvalidTagException(e);
        }
        return result;
    }
}

