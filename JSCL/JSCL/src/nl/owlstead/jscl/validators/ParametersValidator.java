package nl.owlstead.jscl.validators;

import nl.owlstead.jscl.Parameters;

public interface ParametersValidator <T extends Parameters> {
    void validate(T params) throws ValidatorFailedException;
}
