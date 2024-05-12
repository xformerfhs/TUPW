/*
 * SPDX-FileCopyrightText: 2015-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023-2024 Frank Schwab
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
 *     2015-12-20: V1.0.0: Created. fhs
 *     2015-12-21: V1.1.0: Change to correct padding format. fhs
 *     2018-08-21: V1.2.0: Test format 3 and use predictable file. fhs
 *     2020-02-12: V1.3.0: More tests with subject and different versions. fhs
 *     2020-02-27: V1.4.0: Added tests with invalid parameters. fhs
 *     2020-02-28: V1.5.0: Added test with not enough information in source bytes. fhs
 *     2020-03-04: V1.6.0: Split test cases for "FileAndKeyEncryption" and "SplitKeyEncryption". fhs
 *     2020-03-20: V1.7.0: Test new interfaces for byte and character arrays. fhs
 *     2020-05-14: V1.8.0: Correct usage of close interface. fhs
 *     2021-09-03: V1.8.1: Use try-with-resources. fhs
 */
package de.db.bcm.tupw.crypto;

import org.junit.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.Assert.*;

/**
 * Test cases for file and key encryption.
 *
 * @author Frank Schwab
 * @version 1.8.1
 */
public class TestFileAndKeyEncryption {

   /*
    * Private constants
    */
   /**
    * File name for the non-random bytes
    */
   private static final String NOT_RANDOM_FILE_NAME = "_not_random_file_.bin";

   /**
    * HMAC key to be used for encryption
    * <p>
    * This is the static HMAC key which is only known to the program
    * TODO: Do not use this constant byte array. Roll your own!!!!
    */
   private static final byte[] HMAC_KEY = {(byte) 0xC1, (byte) 0xC2, (byte) 0xC8, (byte) 0x0F,
         (byte) 0xDE, (byte) 0x75, (byte) 0xD7, (byte) 0xA9,
         (byte) 0xFC, (byte) 0x92, (byte) 0x56, (byte) 0xEA,
         (byte) 0x3C, (byte) 0x0C, (byte) 0x7A, (byte) 0x08,
         (byte) 0x8A, (byte) 0x6E, (byte) 0xB5, (byte) 0x78,
         (byte) 0x15, (byte) 0x79, (byte) 0xCF, (byte) 0xB4,
         (byte) 0x02, (byte) 0x0F, (byte) 0x38, (byte) 0x3C,
         (byte) 0x61, (byte) 0x4F, (byte) 0x9D, (byte) 0xDB};

   /**
    * Known clear text to encrypt
    */
   private static final String CLEAR_TEXT_V5 = "This#”s?a§StR4nGé€PàS!Wörd9";

   /**
    * Known encrypted text to decrypt
    */
   private static final String SUBJECT = "strangeness+charm";


   /*
    * Public methods
    */
   public TestFileAndKeyEncryption() {
   }

   /**
    * Create nonrandom key file before the test
    */
   @BeforeClass
   public static void setUpClass() {
      //
      // Generate a nonrandom key file with a predictable content, so the tests are reproducible.
      //
      byte[] notRandomBytes = new byte[100000];

      for (int i = 0; i < notRandomBytes.length; i++)
         notRandomBytes[i] = (byte) (0xff - (i & 0xff));

      Path path = Paths.get(NOT_RANDOM_FILE_NAME);

      try {
         Files.write(path, notRandomBytes);
      } catch (Exception e) {
         System.err.print("Could not write to file '" + NOT_RANDOM_FILE_NAME + ": " + e.toString());
      }
   }

   /**
    * Delete nonrandom key file after the test
    */
   @AfterClass
   public static void tearDownClass() {
      Path path = Paths.get(NOT_RANDOM_FILE_NAME);

      try {
         Files.deleteIfExists(path);
      } catch (Exception e) {
         System.err.print("Could not delete file '" + NOT_RANDOM_FILE_NAME + ": " + e.toString());
      }
   }

   @Before
   public void setUp() {
   }

   @After
   public void tearDown() {
   }

   /**
    * Test if the encryption of a given byte array is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryptionForByteArray() {
      final byte[] testByteArray = new byte[256];

      for (int i = 0; i < testByteArray.length; i++)
         testByteArray[i] = (byte) (0xff - i);

      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME)) {
         String encryptedText = myEncryptor.encryptData(testByteArray);

         final byte[] decryptedByteArray = myEncryptor.decryptDataAsByteArray(encryptedText);

         assertArrayEquals("Decrypted byte array is not the same as original byte array", testByteArray, decryptedByteArray);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given character array is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryptionForCharacterArray() {
      final char[] testCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};

      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME)) {
         String encryptedText = myEncryptor.encryptData(testCharArray);

         final char[] decryptedCharArray = myEncryptor.decryptDataAsCharacterArray(encryptedText);

         assertArrayEquals("Decrypted character array is not the same as original character array", testCharArray, decryptedCharArray);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted.
    */
   @Test
   public void TestEncryptionDecryption() {
      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME)) {
         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5);

         String decryptedText = myEncryptor.decryptDataAsString(encryptedText);

         assertEquals("Decrypted text is not the same as original text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted with a subject present.
    */
   @Test
   public void TestEncryptionDecryptionWithSubject() {
      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME)) {
         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5, SUBJECT);

         String decryptedText = myEncryptor.decryptDataAsString(encryptedText, SUBJECT);

         assertEquals("Decrypted text is not the same as original text", CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the decryption of a byte array throws an exception if decrypted as a character array.
    */
   @Test
   public void TestDecryptionToCharArrayWithInvalidByteArray() {
      final byte[] testByteArray = new byte[256];

      for (int i = 0; i < testByteArray.length; i++)
         testByteArray[i] = (byte) (0xff - i);

      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME)) {
         String encryptedText = myEncryptor.encryptData(testByteArray);

         // This must throw an exception as the original byte array is not a valid UTF-8 encoding
         myEncryptor.decryptDataAsCharacterArray(encryptedText);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         String message = e.toString();
         assertTrue("Unexpected exception: " + message, message.contains("MalformedInputException"));
      }
   }

   /**
    * Test if the decryption of a byte array throws an exception if decrypted as a string.
    */
   @Test
   public void TestDecryptionToStringWithInvalidByteArray() {
      final byte[] testByteArray = new byte[256];

      for (int i = 0; i < testByteArray.length; i++)
         testByteArray[i] = (byte) (0xff - i);

      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, NOT_RANDOM_FILE_NAME)) {
         String encryptedText = myEncryptor.encryptData(testByteArray);

         // This must throw an exception as the original byte array is not a valid UTF-8 encoding
         myEncryptor.decryptDataAsString(encryptedText);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         String message = e.toString();
         assertTrue("Unexpected exception: " + message, message.contains("MalformedInputException"));
      }
   }

   /**
    * Test if a file that does not exist is correctly handled.
    */
   @Test
   public void TestFileDoesNotExist() {
      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, "/does/not/exist.txt")) {
         myEncryptor.encryptData(CLEAR_TEXT_V5);

         fail("Expected exception not thrown");
      } catch (IllegalArgumentException e) {
         String exceptionMessage = e.getMessage();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("does not exist"));
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if invalid file name throws an exception.
    */
   @Test
   public void TestFileNameWithInvalidCharacters() {
      String anInvalidFileName = "|<>&";

      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, anInvalidFileName)) {
         myEncryptor.decryptDataAsString(NOT_RANDOM_FILE_NAME);

         myEncryptor.close();

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("Key file path is invalid: "));
      }
   }

   /**
    * Test if null file name throws an exception.
    */
   @Test
   public void TestNullFileName() {
      try (final FileAndKeyEncryption myEncryptor = new FileAndKeyEncryption(HMAC_KEY, null)) {
         myEncryptor.decryptDataAsString(NOT_RANDOM_FILE_NAME);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Key file path is null", e.getMessage());
      }
   }
}
