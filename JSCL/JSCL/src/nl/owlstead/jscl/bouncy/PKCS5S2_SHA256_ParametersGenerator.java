package nl.owlstead.jscl.bouncy;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Copied shamelessly from
 * org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator, changed only
 * the hash algorithm. All rights reserved by Bouncy Castle, see their MIT-like
 * permissive license below.
 * <p>
 * 
 * Copyright (c) 2000 - 2011 The Legion Of The Bouncy Castle
 * (http://www.bouncycastle.org)<br/><br/>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:<br/><br/>
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.<br/><br/>
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.<br/><br/>
 * </p>
 * 
 * @author maartenb
 * 
 */
public class PKCS5S2_SHA256_ParametersGenerator extends PBEParametersGenerator {

    // NOTE this is the only actual change from PKCS5S2ParametersGenerator
    private Mac hMac = new HMac(new SHA256Digest());

    /**
     * construct a PKCS5 Scheme 2 Parameters generator.
     */
    public PKCS5S2_SHA256_ParametersGenerator() {
    }

    private void F(byte[] P, byte[] S, int c, byte[] iBuf, byte[] out,
            int outOff) {
        byte[] state = new byte[hMac.getMacSize()];
        CipherParameters param = new KeyParameter(P);

        hMac.init(param);

        if (S != null) {
            hMac.update(S, 0, S.length);
        }

        hMac.update(iBuf, 0, iBuf.length);

        hMac.doFinal(state, 0);

        System.arraycopy(state, 0, out, outOff, state.length);

        if (c == 0) {
            throw new IllegalArgumentException(
                    "iteration count must be at least 1.");
        }

        for (int count = 1; count < c; count++) {
            hMac.init(param);
            hMac.update(state, 0, state.length);
            hMac.doFinal(state, 0);

            for (int j = 0; j != state.length; j++) {
                out[outOff + j] ^= state[j];
            }
        }
    }

    private void intToOctet(byte[] buf, int i) {
        buf[0] = (byte) (i >>> 24);
        buf[1] = (byte) (i >>> 16);
        buf[2] = (byte) (i >>> 8);
        buf[3] = (byte) i;
    }

    private byte[] generateDerivedKey(int dkLen) {
        int hLen = hMac.getMacSize();
        int l = (dkLen + hLen - 1) / hLen;
        byte[] iBuf = new byte[4];
        byte[] out = new byte[l * hLen];

        for (int i = 1; i <= l; i++) {
            intToOctet(iBuf, i);

            F(password, salt, iterationCount, iBuf, out, (i - 1) * hLen);
        }

        return out;
    }

    /**
     * Generate a key parameter derived from the password, salt, and iteration
     * count we are currently initialised with.
     * 
     * @param keySize
     *            the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    public CipherParameters generateDerivedParameters(int keySize) {
        keySize = keySize / 8;

        byte[] dKey = generateDerivedKey(keySize);

        return new KeyParameter(dKey, 0, keySize);
    }

    /**
     * Generate a key with initialisation vector parameter derived from the
     * password, salt, and iteration count we are currently initialised with.
     * 
     * @param keySize
     *            the size of the key we want (in bits)
     * @param ivSize
     *            the size of the iv we want (in bits)
     * @return a ParametersWithIV object.
     */
    public CipherParameters generateDerivedParameters(int keySize, int ivSize) {
        keySize = keySize / 8;
        ivSize = ivSize / 8;

        byte[] dKey = generateDerivedKey(keySize + ivSize);

        return new ParametersWithIV(new KeyParameter(dKey, 0, keySize), dKey,
                keySize, ivSize);
    }

    /**
     * Generate a key parameter for use with a MAC derived from the password,
     * salt, and iteration count we are currently initialised with.
     * 
     * @param keySize
     *            the size of the key we want (in bits)
     * @return a KeyParameter object.
     */
    public CipherParameters generateDerivedMacParameters(int keySize) {
        return generateDerivedParameters(keySize);
    }
}
