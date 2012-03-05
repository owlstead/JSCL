package nl.owlstead.jscl;

/**
 * Interface to hide specific methods of retrieving CCMParameters 
 * @author maartenb
 *
 */
public interface CCMParameters extends Parameters {
    /**
     * Returns the NONCE for the quested number of bytes.
     * @param nonceSizeBytes the number of bytes to return
     * @return the NONCE, never null, as a byte array
     */
    byte[] getNonce(int nonceSizeBytes);
    
    /**
     * Returns the tag size in bits, used to authenticate the cryptogram.
     * @return the tag size in bits, either 64, 128 or 256 as mentioned in the CCM specifications
     */
    int getTagSizeBits();
}
