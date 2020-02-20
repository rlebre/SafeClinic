package pteidsample;

/**
*   @author lebre
*/
import java.security.*;

public class SecurityUtils {
    public static boolean validateSignature(byte[] data, byte[] signedData, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(data);

        return publicSignature.verify(signedData);
    }
}
