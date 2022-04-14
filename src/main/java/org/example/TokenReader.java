package org.example;

import sun.security.pkcs11.SunPKCS11;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TokenReader {

    private X509Certificate certificate;
    private KeyStore keyStore;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public TokenReader() throws Exception {
        try    {
            // Tenta abrir o Token padrão (ePass2000).
            loadKeyStore("pkcs11.cfg");
        }
        catch (Exception e) {
            // Não conseguiu abrir o token.
            System.out.println("Erro ao ler o token: " + e.getMessage());
            System.out.println("Providers disponíveis:");
            Provider[] providers = Security.getProviders();
            for (Provider provider: providers){
                System.out.println(provider.getInfo());
            }
            throw new Exception(e);
        }
    }

    private void loadKeyStore(String pkcs11Config) throws KeyStoreException, FileNotFoundException {
        Provider pkcs11Provider = new SunPKCS11(new FileInputStream(pkcs11Config));
        Security.addProvider(pkcs11Provider);
        keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);
    }

    public KeyStore openKeyStore(char[] pin) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException {
        keyStore.load(null, pin);
        privateKey = (PrivateKey) keyStore.getKey(keyStore.aliases().nextElement(), pin);
        certificate = (X509Certificate)keyStore.getCertificate(keyStore.aliases().nextElement());
        publicKey = certificate.getPublicKey();
        return keyStore;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

}

