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
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;

import org.bouncycastle.jce.ECNamedCurveTable;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;


public class ecdsa_p256_sha256_java {

    public static byte[] toByteArray(String s) {
        return DatatypeConverter.parseHexBinary(s);
    }


    // using Wycheproof code, since if it exists, don't reinvent it.
    public static BigInteger extractR(byte[] signature) throws Exception {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startR + 2, startR + 2 + lengthR));
    }

    // using Wycheproof code, since if it exists, don't reinvent it.
    public static BigInteger extractS(byte[] signature) throws Exception {
        int startR = (signature[1] & 0x80) != 0 ? 3 : 2;
        int lengthR = signature[startR + 1];
        int startS = startR + 2 + lengthR;
        int lengthS = signature[startS + 1];
        return new BigInteger(Arrays.copyOfRange(signature, startS + 2, startS + 2 + lengthS));
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        SecureRandom random = new SecureRandom();

        if (args.length != 5 && args.length != 4) {
            System.out.println(args.length);
            throw new Exception("Wrong args length");
        }

        byte[] input = toByteArray(args[args.length-1]);

        KeyFactory kf = KeyFactory.getInstance("ECDSA","BC");
        Signature signer = Signature.getInstance("SHA256withECDSA","BC");
        String name = "secp256r1";

        // inspired from https://stackoverflow.com/questions/33218674/how-to-make-a-bouncy-castle-ecpublickey
        ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec(name);
        ECParameterSpec params = new ECNamedCurveSpec(name, parameterSpec.getCurve(),parameterSpec.getG(), parameterSpec.getN(), parameterSpec.getH(), parameterSpec.getSeed());
        


        if (args.length ==  4) {
            ECPrivateKey priKey = (ECPrivateKey) kf.generatePrivate(
                    new ECPrivateKeySpec(
                        new BigInteger(args[2],16),
                        params)
                    );

            signer.initSign(priKey);

            // generate a signature
            signer.update(input);
            byte[] signature = signer.sign();

            String r = String.format("%064x", (extractR(signature)));
            String s = String.format("%064x", (extractS(signature)));
            System.out.println(r);
            System.out.println(s);
        } else {
            BigInteger r = new BigInteger(args[2], 16);
            BigInteger s = new BigInteger(args[3], 16);

            ECPoint point = new ECPoint(
                        new BigInteger(args[0], 16),
                        new BigInteger(args[1], 16)
                        );

            ECPublicKey pubKey = (ECPublicKey) kf.generatePublic(new ECPublicKeySpec(point, params));

            // verify a signature
            signer.initVerify(pubKey);
            signer.update(input);

            // using Wycheproof code, since if it exists, don't reinvent it.
            byte[] rb = r.toByteArray();
            byte[] sb = s.toByteArray();
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
