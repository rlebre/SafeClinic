package pteidsample;

import pt.gov.cartaodecidadao.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class CC {
    static boolean AUTHENTICATION_KEY_PAIR = false;
    static boolean SIGNATURE_KEY_PAIR = true;

    static {
        try {
            System.loadLibrary("pteidlibj");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Native code library failed to load. \n" + e);
            System.exit(1);
        }
    }

    private PTEID_Card card;
    private PTEID_EIDCard eidCard;
    private Certificate signatureCertificate;
    private Certificate authenticationCertificate;

    private CC() throws PTEID_Exception {
        PTEID_ReaderSet.initSDK();
        PTEID_ReaderContext context = PTEID_ReaderSet.instance().getReader();

        this.card = context.getCard();
        this.eidCard = context.getEIDCard();
        this.authenticationCertificate = getCertificate(CC.AUTHENTICATION_KEY_PAIR);
        this.signatureCertificate = getCertificate(CC.SIGNATURE_KEY_PAIR);
    }

    public static CC getInstance() {
        try {
            return new CC();
        } catch (PTEID_Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] sign(String message, boolean key) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = digest.digest(message.getBytes());

        return this.sign(messageHash, key);
    }


    public byte[] sign(byte[] messageHash, boolean key) {
        PTEID_ByteArray pteidDataHash = new PTEID_ByteArray(messageHash, messageHash.length);
        PTEID_ByteArray signedBytes = null;
        try {
            signedBytes = card.Sign(pteidDataHash, key);
        } catch (PTEID_Exception e) {
            e.printStackTrace();
        }

        return signedBytes.GetBytes();
    }

    public boolean validateSignature(String data, byte[] signedData, boolean isSignatureCertificate) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return validateSignature(data.getBytes(), signedData, isSignatureCertificate);
    }

    public boolean validateSignature(byte[] data, byte[] signedData, boolean isSignatureCertificate) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        if (isSignatureCertificate == CC.SIGNATURE_KEY_PAIR) {
            return SecurityUtils.validateSignature(data, signedData, this.getSignaturePublicKey());
        } else {
            return SecurityUtils.validateSignature(data, signedData, this.getAuthenticationPublicKey());
        }
    }

    public Certificate getSignatureCertificate() {
        return this.signatureCertificate;
    }

    public Certificate getAuthenticationCertificate() {
        return this.authenticationCertificate;
    }

    public PublicKey getSignaturePublicKey() {
        return this.signatureCertificate.getPublicKey();
    }

    public PublicKey getAuthenticationPublicKey() {
        return this.authenticationCertificate.getPublicKey();
    }

    private Certificate getCertificate(boolean isSignatureCertificate) throws PTEID_Exception {
        PTEID_Certificate signatureCertificate = this.eidCard.getSignature();
        PTEID_Certificate authenticationCertificate = this.eidCard.getAuthentication();

        byte[] signCertificateBytes = signatureCertificate.getCertData().GetBytes();
        byte[] authenCertificateBytes = authenticationCertificate.getCertData().GetBytes();

        // type of certificate
        CertificateFactory certFactory, certFactory2 = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
            InputStream inSignatureCert = new ByteArrayInputStream(signCertificateBytes);
            certFactory2 = CertificateFactory.getInstance("X.509");
            InputStream inAuthenticationCert = new ByteArrayInputStream(authenCertificateBytes);

            if (isSignatureCertificate) {
                return certFactory.generateCertificate(inSignatureCert);
            } else {
                return certFactory2.generateCertificate(inAuthenticationCert);
            }
        } catch (CertificateException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void close() {
        try {
            PTEID_ReaderSet.releaseSDK();
        } catch (PTEID_Exception e) {
            e.printStackTrace();
        }
    }
}
