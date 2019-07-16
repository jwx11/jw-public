package digest;

import java.io.File;
import java.io.FileInputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;

public class Digest {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage : java digest.Digest algorithm filename");
            System.exit(1);
        }
        String algorithm = toAlgorithmName(args[0]);
        String filename = args[1];

        File file = new File(filename);
        if (!file.exists()) {
            System.err.println("[ERROR] File not found : " + filename);
            System.exit(1);
        }

        process(algorithm, file);
    }

    private static void process(String algorithm, File file) throws Exception {
        byte[] result = digest(algorithm, file);
        System.out.println(toHex(result) + "\t" + file.getName());
    }

    private static byte[] digest(String algorithm, File file) throws  Exception {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        DigestInputStream is = new DigestInputStream(new FileInputStream(file), md);
        byte[] buffer = new byte[4096];
        while (is.read(buffer) > -1) {}
        is.close();
        return md.digest();
    }

    private static String toAlgorithmName(String algorithm) {
        String alg = algorithm.toUpperCase();
        if ("SHA256".equals(algorithm)) {
            alg = "SHA-256";
        } else if ("SHA512".equals(algorithm)) {
            alg = "SHA-512";
        } else if ("SHA384".equals(algorithm)) {
            alg = "SHA-384";
        } else if ("SHA224".equals(algorithm)) {
            alg = "SHA-224";
        }
        return alg;
    }

    // avoid using BC Hex
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    public static String toHex(byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte b : data) {
            int v = b & 0xff;
            builder.append(HEX_CHARS[v >>> 4]);
            builder.append(HEX_CHARS[v & 0x0f]);
        }
        return builder.toString();
    }
}
