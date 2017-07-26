// Please, note that you will need to add a folder called libs here and put
//  the bouncycastle file bcprov-jdk15on-155.jar in it.
// Otherwise the wrapper and the makefile won't work.
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class oaep_rsa2048_java {

    public static String toHexString(byte[] array) {
        return DatatypeConverter.printHexBinary(array).toLowerCase();
    }

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        KeyFactory kf = KeyFactory.getInstance("RSA");

        byte[] input = toByteArray(args[args.length-1]);

        if (args.length < 4) {
            BigInteger modulus = new BigInteger(args[0], 16);
            BigInteger publicExponent = new BigInteger(args[1], 16);

            RSAPublicKeySpec puK = new RSAPublicKeySpec(modulus, publicExponent);
            PublicKey pubKey = kf.generatePublic(puK);
            
            cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
            byte[] cipherText = cipher.doFinal(input);
            System.out.println(toHexString(cipherText));
        } else {
            BigInteger prime1 = new BigInteger(args[0], 16);
            BigInteger prime2 = new BigInteger(args[1], 16);
            BigInteger modulus = prime1.multiply(prime2);
            BigInteger publicExponent = new BigInteger(args[2], 16);
            BigInteger privateExponent = new BigInteger(args[3], 16);
            BigInteger exponent1 = privateExponent.mod(prime1.subtract(BigInteger.ONE));
            BigInteger exponent2 = privateExponent.mod(prime2.subtract(BigInteger.ONE));
            BigInteger coefficient = prime2.modInverse(prime1);
            
            RSAPrivateKey pKy = new RSAPrivateKey(modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient);
            PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(pKy.getEncoded()));
            
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            byte[] plainText = cipher.doFinal(input);
            System.out.println(toHexString(plainText));
        }
    }
}
