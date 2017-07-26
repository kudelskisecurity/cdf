// Please, note that you will need to add a folder called libs here and put
//  the bouncycastle file bcprov-jdk15on-155.jar in it.
// Otherwise the wrapper and the makefile won't work.
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.Security;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAParameters;
import java.util.Arrays;

import org.bouncycastle.crypto.params.DSAKeyGenerationParameters;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

public class dsa_sha256_java {

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }

    private static BigInteger extractR(byte[] signature) throws Exception {
        int lengthR = signature[3];
        return new BigInteger(Arrays.copyOfRange(signature, 4, 4 + lengthR));
    }

    private static BigInteger extractS(byte[] signature) throws Exception {
        int lengthR = signature[3];
        int startS = 4 + lengthR;
        int lengthS = signature[startS + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        if (args.length != 7 && args.length != 6) {
            System.out.println(args.length);
            throw new Exception("Wrong args length");
        }

        //        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        //        KeyFactory kf = KeyFactory.getInstance("RSA");

        byte[] input = toByteArray(args[args.length-1]);
        BigInteger p = new BigInteger(args[0], 16);
        BigInteger q = new BigInteger(args[1], 16);
        BigInteger g = new BigInteger(args[2], 16);

        KeyFactory kf = KeyFactory.getInstance("DSA");
        Signature signer = Signature.getInstance("SHA256WITHDSA");

        if (args.length ==  6) {
            BigInteger y = new BigInteger(args[3], 16);
            BigInteger x = new BigInteger(args[4], 16);

            DSAPrivateKey priv = (DSAPrivateKey) kf.generatePrivate(new DSAPrivateKeySpec(x, p, q, g));

//            DSAParameters paramdsa = new DSAParameters(p, q, g) ;
//            DSAKeyGenerationParameters test = new DSAKeyGenerationParameters(new SecureRandom(),paramdsa);
//            DSAKeyPairGenerator gen = new DSAKeyPairGenerator();
//            gen.init(test);
//            AsymmetricCipherKeyPair testGenKey = (AsymmetricCipherKeyPair) gen.generateKeyPair();
//            DSAKeyParameters testKey = (DSAKeyParameters) testGenKey.getPublic();
//            System.out.println(testKey.getParameters().getG());

            signer.initSign(priv);
            // generate a signature
            signer.update(input);
            byte[] signature = signer.sign();

            String r = String.format("%040x", (extractR(signature)));
            String s = String.format("%040x", (extractS(signature)));
            System.out.println(r);
            System.out.println(s);
        } else {
            BigInteger y = new BigInteger(args[3], 16);
            BigInteger r = new BigInteger(args[4], 16);
            BigInteger s = new BigInteger(args[5], 16);

            DSAPublicKey pubKey = (DSAPublicKey) kf.generatePublic(new DSAPublicKeySpec(y, p, q, g));
            // verify a signature
            signer.initVerify(pubKey);
            signer.update(input);
            // need to change that to use our values
            // convert (r, s) to ASN.1 DER encoding
            // assuming you have r and s as !!positive!! BigIntegers
            byte[] rb = r.toByteArray();
            byte[] sb = s.toByteArray(); // sign-padded if necessary
            // these lines are more verbose than necessary to show the structure
            // compiler will fold or you can do so yourself 
            int off = (2 + 2) + rb.length;
            int tot = off + (2 - 2) + sb.length;
            byte[] der = new byte[tot + 2];
            der[0] = 0x30;
            der[1] = (byte) (tot & 0xff);
            der[2 + 0] = 0x02;
            der[2 + 1] = (byte) (rb.length & 0xff);
            System.arraycopy(rb, 0, der, 2 + 2, rb.length);
            der[off + 0] = 0x02;
            der[off + 1] = (byte) (sb.length & 0xff);
            System.arraycopy(sb, 0, der, off + 2, sb.length);
            if (signer.verify(der))
            {
                System.out.println("true");
            }
            else
            {
                System.out.println("false");
            }
        }
    }
}
