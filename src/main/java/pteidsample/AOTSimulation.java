package pteidsample;

import ieeta.aot.AuthRequest;
import ieeta.aot.EncryptedData;
import ieeta.aot.Utils;
import ieeta.aot.node.NodeServer;
import ieeta.aot.node.NodeSession;
import ieeta.aot.terminal.Terminal;
import ieeta.aot.terminal.TerminalSession;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class AOTSimulation {

    public static void main(String[] args) {
        final Terminal term = Utils.genTerminal();
        final NodeServer node = Utils.genNodeServer();
        final CC cc = CC.getInstance();

        // Assuming that terminal key and operator key is already certified by the node

        final TerminalSession tSession = term.genSession(data -> {
            System.out.println("Token: " + Utils.bytesToHex(data));
            System.out.println("SHA-256(Token): " + Utils.bytesToHex(Utils.hash(data)));


            // perform a Citizens Card signature on "data" -> "sigBytes"
            byte[] sigBytes = cc.sign(Utils.hash(data), CC.SIGNATURE_KEY_PAIR);
            byte[] pubKey = cc.getSignaturePublicKey().getEncoded();

            return new AuthRequest.ExtSignature(pubKey, sigBytes);
        });

        // TODO: AuthRequest is sent via network

        // TODO: in real applications both keys should be checked before binding the session (auth.termKey & auth.extSig.operKey)
        final NodeSession nSession = node.bindSession(tSession.req, cdata -> {
            System.out.println("Token: " + Utils.bytesToHex(cdata.data));

            //TODO: check if "cdata.time" is in acceptable range

            try {
                PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(cdata.extSig.operKey));
                return SecurityUtils.validateSignature(cdata.data, cdata.extSig.sig, publicKey);
            } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | InvalidKeySpecException e) {
                return false;
            }
        });

        // TODO: AuthResponse is sent via network

        // set k key from the node response
        tSession.setK(node.pkey, nSession.resp);

        // simulation of encrypted transmission
        final EncryptedData ciphertext = nSession.encrypt("Testing sending data!".getBytes());
        final byte[] plaintext = tSession.dencrypt(ciphertext);

        System.out.println(new String(plaintext));

        cc.close();
    }
}