package nl.owlstead.jscl.validators;

public class ValidatorFailedException extends Exception {

    private static final long serialVersionUID = 1L;

    public ValidatorFailedException(String message) {
        super(message);
    }
    
}
