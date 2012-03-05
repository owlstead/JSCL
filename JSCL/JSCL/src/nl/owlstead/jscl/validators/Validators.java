package nl.owlstead.jscl.validators;

import nl.owlstead.jscl.CCMParameters;
import nl.owlstead.jscl.PBKDFParameters;

public final class Validators {
    private Validators() {
        // disallow instantiation
    }
    
    public static PBKDFParametersValidator getPermissivePBKDFParametersValidator () {
        return new PBKDFParametersValidator() {
            
            @Override
            public void validate(PBKDFParameters params) throws ValidatorFailedException {
                
            }
        };
    }

    public static PBKDFParametersValidator getMinimumStrengthPBKDFParametersValidator () {
        return new PBKDFParametersValidator() {
            
            @Override
            public void validate(PBKDFParameters params) throws ValidatorFailedException {
                if (params.getIterations() < 1000) {
                    throw new ValidatorFailedException("Number of iterations is too low");
                }
                
                if (params.getKeySize() < 128) {
                    throw new ValidatorFailedException("Key size too small");
                }

//                byte[] salt = params.getSalt();
//                if (salt.length < 8) {
//                    throw new ValidatorFailedException("Salt should be at least 8 bytes");
//                }
                
//                int i;
//                for (i = 0; i < salt.length; i++) {
//                    if (salt[i] != 0) {
//                        break;
//                    }
//                }
                
//                if (i != salt.length) {
//                    throw new ValidatorFailedException("Salt should not contain only zeros");
//                }
            }
        };
    }
    
    public static CCMParametersValidator getgetMinimumStrengthCCMParametersValidator () {
        return new CCMParametersValidator() {
            
            @Override
            public void validate(CCMParameters params) throws ValidatorFailedException {
                // do nothing, anything's good
            }
        };
    }

}
