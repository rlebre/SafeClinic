package pteidsample;

import pt.gov.cartaodecidadao.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class AOTMainTest {

    public static void main(String[] args) {
        //todo();
        try {
            todo2();
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
//        final Terminal term = Utils.genTerminal();
//        final NodeServer node = Utils.genNodeServer();
//
//        // Assuming that terminal key and operator key is already certified by the node
//
//        final TerminalSession tSession = term.genSession(node.pkey);
//        final Authorization auth = tSession.authorize(data -> {
//            System.out.println("Token: " + Utils.bytesToHex(data));
//            System.out.println("SHA-256(Token): " + Utils.bytesToHex(Utils.hash(data)));
//
//            // TODO: perform a Citizens Card signature on "data" -> "sigBytes"
//
//            // return new ExtSignature(pubKey, sigBytes);
//            return null;
//        });
//
//        // TODO: authorization is sent via network
//
//        // TODO: in real applications both keys should be checked before binding the session (auth.termKey & auth.extSig.operKey)
//        final NodeSession nSession = node.bindSession(auth, cdata -> {
//            System.out.println("Token: " + Utils.bytesToHex(cdata.data));
//
//            //TODO: check if "cdata.time" is in acceptable range
//            //TODO: perform a Citizens Card signature check on "cdata.data" using "cdata.extSig"
//
//            return true;
//        });
//
//        // TODO: encrypt and send data Ek[data]
//        final byte[] ciphertext = nSession.encrypt("Testing sending data!".getBytes());
//
//        // TODO: send Ek1[k2] when consent is confirmed
//        tSession.setK(nSession.encK2);
//        final byte[] plaintext = tSession.dencrypt(ciphertext);
//
//        System.out.println(new String(plaintext));
    }


    public static void todo2() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        CC cc = CC.getInstance();

        if (cc == null) {
            System.err.println("Error initializing Portuguese Citizen Card");
            return;
        }

        String data = "data_to_sign";
        byte[] signature = cc.sign(data, CC.SIGNATURE);
        System.out.println(cc.validateSignature(data, signature, CC.SIGNATURE));

        cc.close();
    }

    public static void todo() {
        try {
            PTEID_ReaderSet.initSDK();
            PTEID_ReaderContext context = PTEID_ReaderSet.instance().getReader();

            // message to sign
            byte[] data = "data_to_sign".getBytes();

            // generate message hash SHA256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] dataHash = digest.digest(data);

            // convert hash in PTEID object
            PTEID_ByteArray pteidDataHash = new PTEID_ByteArray(dataHash, dataHash.length);

            // sign the hash with the card
            PTEID_Card card = context.getCard();
            PTEID_ByteArray signedBytes = card.Sign(pteidDataHash, true);

            // get signature certificate
            PTEID_EIDCard eidCard = context.getEIDCard();
            PTEID_Certificate signatureCertificate = eidCard.getSignature();
            byte[] eidCertificate = signatureCertificate.getCertData().GetBytes();

            // type of certificate
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(eidCertificate);

            // generate certificate (according to Java API)
            Certificate certif = certFactory.generateCertificate(in);

            // get certificate public key
            PublicKey publicKey = certif.getPublicKey();

            // verify signature
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
            publicSignature.update(data);
            boolean signCorrect = publicSignature.verify(signedBytes.GetBytes());

            System.out.printf("\n----------------- CERTIFICATE ------------------\n%s\n", certif);
            System.out.printf("\n------------------ PUBLIC KEY ------------------\n%s\n", publicKey);
            System.out.printf("\n---------------- SIGNATURE CHECK ---------------\nCorrect signature: %s", signCorrect);
        } catch (PTEID_Exception | CertificateException | SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } finally {
            try {
                PTEID_ReaderSet.releaseSDK();
            } catch (PTEID_Exception e) {
                e.printStackTrace();
            }
        }
    }
}