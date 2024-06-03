/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.cmsc125;

/**
 *
 * @author Shaw Jie Yao
 */
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Scanner;
import java.util.Random;

public class CMSC125MP2 {
    public static int[] generateTwoDifferentPrimes() {
        Random random = new Random();
        int prime1 = 0;
        int prime2 = 0;

        while (true) {
            int candidate = random.nextInt(1000) + 1;
            if (isPrime(candidate) && candidate > 100) {
                prime1 = candidate;
                break;
            }
        }

        while (true) {
            int candidate = random.nextInt(1000) + 1;
            if (isPrime(candidate) && candidate != prime1 && candidate > 100) {
                prime2 = candidate;
                break;
            }
        }

        return new int[]{prime1, prime2};
    }

    public static boolean isPrime(int num) {
        if (num <= 1) {
            return false;
        }
        for (int i = 2; i <= Math.sqrt(num); i++) {
            if (num % i == 0) {
                return false;
            }
        }
        return true;
    }

    public class RSA {
        private BigInteger e;
        private BigInteger d;
        private BigInteger n;

        public RSA(BigInteger p, BigInteger q) {
            n = p.multiply(q);
            System.out.println("N (pq) is equal to " + n);
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
            System.out.println("Phi (p-1)(q-1) is equal to " + phi);
            e = calculateRelativelyPrime(phi);
            d = calculatePublicKey(e, phi);
        }

        public BigInteger encrypt(BigInteger message) {
            return message.modPow(e, n);
        }

        public BigInteger decrypt(BigInteger message) {
            return message.modPow(d, n);
        }

        private BigInteger calculateRelativelyPrime(BigInteger phi) {
            BigInteger candidate = BigInteger.valueOf(2);
            while (!gcd(phi, candidate).equals(BigInteger.ONE)) {
                candidate = candidate.add(BigInteger.ONE);
            }
            if (candidate.compareTo(phi) >= 0) {
                throw new IllegalArgumentException("No valid relatively prime number found.");
            }
            System.out.println("The Lowest prime relatively prime to phi is " + candidate);
            return candidate;
        }

        private BigInteger calculatePublicKey(BigInteger e, BigInteger phi) {
            BigInteger x = BigInteger.ONE;
            while (!e.multiply(x).mod(phi).equals(BigInteger.ONE)) {
                x = x.add(BigInteger.ONE);
            }
            return x;
        }

        public BigInteger gcd(BigInteger a, BigInteger b) {
            while (!b.equals(BigInteger.ZERO)) {
                BigInteger temp = b;
                b = a.mod(b);
                a = temp;
            }
            return a;
        }

        public BigInteger runRSA(BigInteger message, boolean isEncrypt) {
            if (isEncrypt) {
                BigInteger ciphertext = encrypt(message);
                System.out.println("Original Message: " + message);
                System.out.println("Encrypted Message: " + ciphertext);
                return ciphertext;
            } else {
                BigInteger plaintext = decrypt(message);
                System.out.println("Encrypted Message: " + message);
                System.out.println("Decrypted Message: " + plaintext);
                return plaintext;
            }
        }

        public String runRSAString(String message, boolean isEncrypt) {
            if (isEncrypt) {
                System.out.println("Original Message: " + message);
                StringBuilder encryptedMessage = new StringBuilder();

                // Encrypt each character
                for (char ch : message.toCharArray()) {
                    BigInteger charValue = BigInteger.valueOf((int) ch);
                    BigInteger encryptedChar = encrypt(charValue);
                    encryptedMessage.append(encryptedChar.toString()).append(" ");
                }

                System.out.println("Encrypted Message: " + encryptedMessage.toString().trim());
                return encryptedMessage.toString().trim();
            } else {
                System.out.println("Encrypted Message: " + message);
                String[] encryptedValues = message.split(" ");
                StringBuilder decryptedMessage = new StringBuilder();

                // Decrypt each character
                for (String value : encryptedValues) {
                    BigInteger encryptedChar = new BigInteger(value);
                    BigInteger decryptedChar = decrypt(encryptedChar);
                    decryptedMessage.append((char) decryptedChar.intValue());
                }

                System.out.println("Decrypted Message: " + decryptedMessage.toString());
                return decryptedMessage.toString();
            }
        }
    }

    public class SHA1 {
        private static int leftRotate(int value, int bits) {
            return (value << bits) | (value >>> (32 - bits));
        }

        public byte[] sha1(byte[] input) {
            int h0 = 0x67452301;
            int h1 = 0xEFCDAB89;
            int h2 = 0x98BADCFE;
            int h3 = 0x10325476;
            int h4 = 0xC3D2E1F0;

            byte[] padded = padMessage(input);
            int[] w = new int[80];

            for (int i = 0; i < padded.length / 64; i++) {
                ByteBuffer buffer = ByteBuffer.wrap(padded, i * 64, 64).order(ByteOrder.BIG_ENDIAN);
                for (int j = 0; j < 16; j++) {
                    w[j] = buffer.getInt();
                }
                for (int j = 16; j < 80; j++) {
                    w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                }

                int a = h0;
                int b = h1;
                int c = h2;
                int d = h3;
                int e = h4;

                for (int j = 0; j < 80; j++) {
                    int f, k;
                    if (j < 20) {
                        f = (b & c) | ((~b) & d);
                        k = 0x5A827999;
                    } else if (j < 40) {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    } else if (j < 60) {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    } else {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }

                    int temp = leftRotate(a, 5) + f + e + k + w[j];
                    e = d;
                    d = c;
                    c = leftRotate(b, 30);
                    b = a;
                    a = temp;
                }

                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
            }

            ByteBuffer result = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN);
            result.putInt(h0).putInt(h1).putInt(h2).putInt(h3).putInt(h4);

            return result.array();
        }

        private byte[] padMessage(byte[] message) {
            int originalLength = message.length;
            int numBits = originalLength * 8;
            int paddingLength = (56 - (originalLength + 1) % 64 + 64) % 64;
            ByteBuffer buffer = ByteBuffer.allocate(originalLength + 1 + paddingLength + 8).order(ByteOrder.BIG_ENDIAN);
            buffer.put(message);
            buffer.put((byte) 0x80);
            for (int i = 0; i < paddingLength; i++) {
                buffer.put((byte) 0);
            }
            buffer.putLong(numBits);
            return buffer.array();
        }

        public String hashToString(String input) {
            byte[] hash = sha1(input.getBytes());
            return bytesToHex(hash);
        }

        private String bytesToHex(byte[] bytes) {
            StringBuilder hexString = new StringBuilder();
            for (byte b : bytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        }
    }

    public void runAlgorithm(String choice, String input) {
        Scanner scanner = new Scanner(System.in);
        switch (choice.toUpperCase()) {
            case "RSA":
                int[] primes = generateTwoDifferentPrimes();
                BigInteger p = BigInteger.valueOf(primes[0]);
                BigInteger q = BigInteger.valueOf(primes[1]);
                System.out.println("Your chosen primes are " + p + " and " + q);
                RSA rsa = new RSA(p, q);

                BigInteger message;
                try {
                    message = new BigInteger(input);
                } catch (NumberFormatException e) {
                    message = null;
                }

                if (message != null) {
                    BigInteger ciphertext = rsa.runRSA(message, true);

                    System.out.print("Would you like to decrypt the encrypted message? (Y/N): ");
                    String decryptChoice = scanner.nextLine();
                    if (decryptChoice.equalsIgnoreCase("Y")) {
                        rsa.runRSA(ciphertext, false);
                    }
                } else {
                    String encryptedMessage = rsa.runRSAString(input, true);

                    System.out.print("Would you like to decrypt the encrypted message? (Y/N): ");
                    String decryptChoice = scanner.nextLine();
                    if (decryptChoice.equalsIgnoreCase("Y")) {
                        rsa.runRSAString(encryptedMessage, false);
                    }
                }
                break;

            case "SHA":
                SHA1 sha = new SHA1();
                String hash = sha.hashToString(input);
                System.out.println("Original Message: " + input);
                System.out.println("SHA-1 Hash: " + hash);
                break;

            default:
                System.out.println("Invalid choice. Please select either RSA or SHA.");
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        CMSC125MP2 mainClass = new CMSC125MP2();

        while (true) {
            System.out.print("Enter the algorithm to use (RSA or SHA) or type 'exit' to quit: ");
            String choice = scanner.nextLine();

            if (choice.equalsIgnoreCase("exit")) {
                break;
            } else if (choice.equalsIgnoreCase("RSA")) {
                System.out.print("Enter the value to be encrypted: ");
                String input = scanner.nextLine();
                mainClass.runAlgorithm(choice, input);
            } else if (choice.equalsIgnoreCase("SHA")) {
                System.out.print("Enter the string to be hashed (for SHA): ");
                String input = scanner.nextLine();
                mainClass.runAlgorithm(choice, input);
            } else {
                System.out.println("Invalid choice. Please select either RSA or SHA.");
            }
        }

        scanner.close();
    }
}

