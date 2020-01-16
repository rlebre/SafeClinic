package pteidsample;

import ieeta.aot.Authorization;
import ieeta.aot.Utils;
import ieeta.aot.node.NodeServer;
import ieeta.aot.node.NodeSession;
import ieeta.aot.terminal.Terminal;
import ieeta.aot.terminal.TerminalSession;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class AOTSimulation {

    public static void main(String[] args) {
        final Terminal term = Utils.genTerminal();
        final NodeServer node = Utils.genNodeServer();
        final CC cc = CC.getInstance();

        if (cc == null) {
            System.err.println("Error initializing Portuguese Citizen Card");
            System.exit(1);
        }

        // Assuming that terminal key and operator key is already certified by the node
        final TerminalSession tSession = term.genSession(node.pkey);
        final Authorization auth = tSession.authorize(data -> {
            System.out.println("Token: " + Utils.bytesToHex(data));
            System.out.println("SHA-256(Token): " + Utils.bytesToHex(Utils.hash(data)));

            // perform a Citizens Card signature on "data" -> "sigBytes"
            byte[] sigBytes = cc.sign(Utils.hash(data), CC.SIGNATURE_KEY_PAIR);
            byte[] pubKey = cc.getSignaturePublicKey().getEncoded();

            return new Authorization.ExtSignature(pubKey, sigBytes);
        });

        // TODO: authorization is sent via network

        // TODO: in real applications both keys should be checked before binding the session (auth.termKey & auth.extSig.operKey)
        final NodeSession nSession = node.bindSession(auth, cdata -> {
            System.out.println("Token: " + Utils.bytesToHex(cdata.data));

            //TODO: check if "cdata.time" is in acceptable range

            // perform a Citizens Card signature check on "cdata.data" using "cdata.extSig"
            try {
                return cc.validateSignature(cdata.data, cdata.extSig.sig, CC.SIGNATURE_KEY_PAIR);
            } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
                return false;
            }
        });

        // TODO: encrypt and send data Ek[data]
        final byte[] ciphertext = nSession.encrypt("Testing sending data!".getBytes());

        // TODO: send Ek1[k2] when consent is confirmed
        tSession.setK(nSession.encK2);
        final byte[] plaintext = tSession.dencrypt(ciphertext);

        System.out.println(new String(plaintext));

        cc.close();
    }
}