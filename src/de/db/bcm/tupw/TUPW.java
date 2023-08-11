/*
 * SPDX-FileCopyrightText: 2022-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023 Frank Schwab
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Frank Schwab
 *
 * Changes:
 *     2017-03-30: V1.0.0: Created. fhs
 *     2017-04-12: V1.0.1: Moved secure random number generator to class constant. fhs
 *     2017-05-23: V1.0.2: Corrected spelling of "aesCipher". fhs
 *     2017-06-01: V1.0.3: Modified StringSplitter. fhs
 *     2017-11-09: V1.0.4: Use CFB modus to thwart padding oracle attacks. fhs
 *     2017-12-19: V2.0.0: Use CFB8 modus and arbitrary tail padding to thwart padding oracle attacks,
 *                         Refactored interface to encryption and decryption. fhs
 *     2017-12-20: V2.1.0: Encrypt/decrypt only one item. fhs
 *     2018-01-30: V3.0.0: Only plain output, input also from stdin to make the program usable in a pipe. fhs
 *     2018-02-01: V3.0.1: Input from stdin must not exceed 50 MB. fhs
 *     2018-05-17: V3.1.0: Use CTR mode to squash ciphertext manipulation attacks. fhs
 *     2018-06-13: V3.2.0: Use constant time HMAC compare to squash timing attacks. fhs
 *     2018-08-07: V3.2.1: Some small improvements. fhs
 *     2018-08-16: V3.2.2: Added some "finals". fhs
 *     2018-08-17: V3.3.0: Use blinding and random padding. fhs
 *     2019-03-06: V3.3.1: Minor changes in SecureSecretKeySpec. fhs
 *     2019-03-07: V4.0.0: Add a "subject" to the command line that will change the encryption key. fhs
 *     2019-03-07: V4.0.1: Strengthen test for invalid blinding data. fhs
 *     2019-03-07: V4.1.0: Correct handling of keys with subject parameter. fhs
 *     2020-03-06: V4.1.1: Simply read from System.in. fhs
 *     2020-03-27: V4.1.2: Adapted to new interface. fhs
 *     2020-03-27: V4.1.3: Show usage with char[] on decryption. fhs
 */
package de.db.bcm.tupw;

import de.db.bcm.tupw.crypto.FileAndKeyEncryption;
import de.db.bcm.tupw.numbers.Xoroshiro128plusplus;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Example program to calculate the encryption of user and password for
 * technical users. To be called from the command line.
 *
 * <p>
 * Returns with the following exit codes:
 * 0: Data converted
 * 1: Error during conversion
 * 2: Not enough arguments
 * </p>
 *
 * @author Frank Schwab
 * @version 4.1.3
 */
public class TUPW {
   private static final int MAX_INPUT_BYTES = 50000000;
   private static final int READ_BLOCK_SIZE = 4096;

   /**
    * Implements a method that creates a deterministic HMAC key from
    * a pseudo-random number generator with as fixed key
    *
    * @return The deterministic HMAC key
    */
   private static byte[] createHMACKey() {
      final byte[] result = new byte[32];
      // TODO: Do not use this seed constant. Roll your own!!!!
      final Xoroshiro128plusplus xs128 = new Xoroshiro128plusplus(0x5A7F93DDD402915AL);

      for (int i = 0; i < result.length; i++)
         result[i] = xs128.nextByte();

      return result;
   }

   public static void main(final String[] args) {
      int exitCode = 0;

      if (args.length >= 3) {
         // There are many ways to specify the HMAC key.
         // One way is simply to use a static HMAC key which is only known to the program.
         // TODO: Do not use this constant byte array. Roll your own!!!!
         final byte[] HMAC_KEY = {(byte) 0x53, (byte) 0x67, (byte) 0xC3, (byte) 0x59,
                  (byte) 0x4B, (byte) 0x46, (byte) 0x0F, (byte) 0xFA,
                  (byte) 0x15, (byte) 0x21, (byte) 0x13, (byte) 0x6C,
                  (byte) 0x7F, (byte) 0xDD, (byte) 0x33, (byte) 0x57,
                  (byte) 0x26, (byte) 0xF3, (byte) 0x10, (byte) 0xA0,
                  (byte) 0xE9, (byte) 0x16, (byte) 0xA4, (byte) 0x2E,
                  (byte) 0x9E, (byte) 0x15, (byte) 0x8E, (byte) 0xF4,
                  (byte) 0x03, (byte) 0x04, (byte) 0xAA, (byte) 0x2C};

         // Another way is to calculate the HMAC key in a deterministic way
         // TODO: Do not use both HMAC keys. Choose one of them. You may keep the constant HMAC_KEY as a decoy.
         final byte[] CALCULATED_HMAC_KEY = createHMACKey();

         // There are many other ways to create a HMAC key. Use you imagination.
         try (FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, args[1])) {
            String subject = "";
            int itemIndex = 2;

            if (args.length >= 4) {
               subject = args[2];
               itemIndex++;
            }

            if (args[0].substring(0, 1).toLowerCase().equals("e")) {
               System.out.println(myEncryptor.encryptData(getInputFromWhereEver(args[itemIndex]), subject));
            } else {
               final char[] decryptedOutput = myEncryptor.decryptDataAsCharacterArray(getInputFromWhereEver(args[itemIndex]), subject);

               System.out.println(decryptedOutput);

               // Clear decrypted output after use
               Arrays.fill(decryptedOutput, '\0');
            }
         } catch (final Exception e) {
            e.printStackTrace();
            exitCode = 1;
         }
      } else {
         System.err.println("Not enough arguments.");
         System.err.println();
         System.err.println("Usage:");
         System.err.println("   tupw.jar encrypt {keyfile} [subject] {clearItem}");
         System.err.println("   tupw.jar decrypt {keyfile} [subject] {encryptedItem}");
         System.err.println();
         System.err.println("If {clearItem}, or {encryptedItem} is '-' input is read from stdin.");
         System.err.println("This makes it possible to use the program in a pipe.");

         exitCode = 2;
      }

      System.exit(exitCode);
   }

   /**
    * Get input either from the command line, or from stdin if third argument
    * is "-"
    *
    * @param anArgument The command line argument that is either the data,
    *                   or "-"
    * @return Data to process
    * @throws IllegalArgumentException if input stream is toot large
    * @throws IOException              if there was an I/O error when reading the input bytes
    */
   static String getInputFromWhereEver(final String anArgument) throws IllegalArgumentException, IOException {
      String result;

      // Get input from System.in, if third argument is "-", or from the 
      // third command line argument, if it is something else
      if (anArgument.equals("-")) {
         result = getSystemInAsString();
      } else {
         result = anArgument;
      }

      return result;
   }

   /**
    * Convert System.in input stream to a <code>String</code>
    *
    * @return Content of InputStream System.in as String
    * @throws IllegalArgumentException if the input stream is too large
    * @throws IOException              if there was an I/O error while reading the input bytes
    */
   static String getSystemInAsString() throws IllegalArgumentException, IOException {
      final ByteArrayOutputStream result = new ByteArrayOutputStream();
      final byte[] buffer = new byte[READ_BLOCK_SIZE];
      int length;

      while ((length = System.in.read(buffer)) != -1) {
         result.write(buffer, 0, length);

         if (result.size() > MAX_INPUT_BYTES)
            throw new IllegalArgumentException("Input from input stream is larger than " + String.format("%,d", MAX_INPUT_BYTES) + " bytes");
      }

      // Convert to String with Java file encoding
      return result.toString(System.getProperty("file.encoding")).trim(); // Need trim here as pipes append an unnecessary newline
   }
}
