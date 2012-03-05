package nl.owlstead.jscl;

import java.util.Arrays;

import nl.owlstead.jscl.bouncy.PKCS5S2_SHA256_ParametersGenerator;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Strings;

public class PBKDF2_SHA256 {

    private final PKCS5S2_SHA256_ParametersGenerator gen;
    
    private PBKDFParameters params;
    
    enum State {
        INSTANTIATED,
        INITIALIZED,
        ;
    }
    
    private State state; 
    
    public PBKDF2_SHA256() {
        gen = new PKCS5S2_SHA256_ParametersGenerator();
        state = State.INSTANTIATED;
    }
    
    public void init(final PBKDFParameters params) {
        this.params = params;
        state = State.INITIALIZED;
    }
    
    public KeyParameter generateKey(final byte[] salt, final char[] password) {
        // lets not use String, as we cannot destroy strings, BC to the rescue!
        final byte[] pwBytes = Strings.toUTF8ByteArray(password);
        
        gen.init(pwBytes, salt, params.getIterations());
        final KeyParameter key = (KeyParameter) gen.generateDerivedMacParameters(params.getKeySize());
        
        // use for/next loop for older Java versions
        Arrays.fill(pwBytes, 0, pwBytes.length, (byte) 0);
        
        // returns the bytes within the key, so do not destroy key
        return key;
    }
}
