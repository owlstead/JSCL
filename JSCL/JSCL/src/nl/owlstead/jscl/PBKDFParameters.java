package nl.owlstead.jscl;

/**
 * Returns the PBE Parameters, used by the PBKDF2 function.
 * The underlying algorithms are supposed to be known beforehand. 
 * @author maartenb
 *
 */
public interface PBKDFParameters extends Parameters {
//    /**
//     * Returns the salt as a byte array; changes on this byte array may be reflected by the state of this
//     * instance of PBEParameters
//     * @return the salt as a byte array
//     */
//    byte[] getSalt();
    
    /**
     * Returns the number of iterations that the PBKDF function should perform.
     * @return
     */
    int getIterations();
    
    
    /**
     * Returns the size of the key in bits.
     * @return the size of the key
     */
    int getKeySize();
}
