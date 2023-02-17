

import java.math.BigInteger;
import javax.crypto.spec.*;

public class Skip {
    // http://skip.incog.com/spec/numbers.html
    // Simple Key Management for Internet Protocols – SKIP.
    // Using DH (Diffie-Hellman standard). 1024 DH parameter defined by SKIP. First
    // 79 bytes of ASCII
    // representation of a quote by Gandhi. "Whatever you do is insignificant, but
    // it is very important that
    // you do it." 512, 1024, and 2048 bit modulus parameters are supported. The
    // resulting keys are
    // the length of the modulus, i.e., 512, 1024, or 2048 bits.

    private static final String skip1024String = 
            "F488FD584E49DBCD" + "20B49DE49107366B" + "336C380D451D0F7C" + "88B31C7C5B2D8EF6" +
            "F3C923C043F0A55B" + "188D8EBB558CB85D" + "38D334FD7C175743" + "A31D186CDE33212C" +
            "B52AFF3CE1B12940" + "18118D7C84A70A72" + "D686C40319C80729" + "7ACA950CD9969FAB" +
            "D00A509B0246D308" + "3D66A45D419F9C7C" + "BD894B221926BAAB" + "A25EC355E92F78C7";

    // Create modulus from string => “p”
    private static final BigInteger skip1024Modulus = new BigInteger(skip1024String, 16);

    // Base => “g”
    private static final BigInteger skip1024Base = BigInteger.valueOf(2);

    // DH parameter specification
    public static final DHParameterSpec sDHParameterSpec = new DHParameterSpec(skip1024Modulus, skip1024Base);
}