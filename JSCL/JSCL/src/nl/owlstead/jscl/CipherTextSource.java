package nl.owlstead.jscl;

/**
 * Generic class to allow for multiple sources of cipher text.
 * @author maartenb
 */
public interface CipherTextSource {
    /**
     * Altering the returned cipher text may influence the buffered cipher text.
     * @return the cipher text as an array of bytes, never null
     */
    byte[] getCipherText();
}
