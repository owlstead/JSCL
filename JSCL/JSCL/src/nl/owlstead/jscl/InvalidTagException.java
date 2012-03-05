package nl.owlstead.jscl;


public class InvalidTagException extends Exception {

    private static final long serialVersionUID = 1L;

    public InvalidTagException(final Exception e) {
        super(e);
    }
}
