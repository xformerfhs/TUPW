/*
 * SPDX-FileCopyrightText: 2020-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023-2025 Frank Schwab
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
 *     2020-03-04: V1.0.0: Created. fhs
 *     2020-03-09: V1.0.1: Test 0 length source byte array. fhs
 *     2020-03-20: V1.1.0: Test new interfaces for byte and character arrays. fhs
 *     2020-05-14: V1.2.0: More tests for basic encryption/decryption and usage of the close interface. fhs
 *     2021-09-03: V1.2.1: Use try-with-resources. fhs
 *     2025-02-18: V2.0.0: Replace all string encryptions and decryptions with character arrays. fhs
 */
package de.xformerfhs.crypto;

import de.xformerfhs.numbers.Xoroshiro128plusplus;
import org.junit.*;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Test cases for file and key encryption.
 *
 * @author Frank Schwab
 * @version 2.0.0
 */
public class TestSplitKeyEncryption {

   /*
    * Private constants
    */

   /**
    * HMAC key to be used for encryption
    * <p>
    * This is the static HMAC key which is only known to the program
    * TODO: Do not use this constant byte array. Roll your own!!!!
    */
   private static final byte[] CONSTANT_HMAC_KEY = {
         (byte) 0xC1, (byte) 0xC2, (byte) 0xC8, (byte) 0x0F,
         (byte) 0xDE, (byte) 0x75, (byte) 0xD7, (byte) 0xA9,
         (byte) 0xFC, (byte) 0x92, (byte) 0x56, (byte) 0xEA,
         (byte) 0x3C, (byte) 0x0C, (byte) 0x7A, (byte) 0x08,
         (byte) 0x8A, (byte) 0x6E, (byte) 0xB5, (byte) 0x78,
         (byte) 0x15, (byte) 0x79, (byte) 0xCF, (byte) 0xB4,
         (byte) 0x02, (byte) 0x0F, (byte) 0x38, (byte) 0x3C,
         (byte) 0x61, (byte) 0x4F, (byte) 0x9D, (byte) 0xDB};

   /**
    * HMAC key to be used for encryption
    *
    * <p>This is the static HMAC key which is only known to the program</p>
    */
   private static final byte[] COMPUTED_HMAC_KEY = new byte[32];

   /**
    * Default character set for string to byte conversion
    */
   private static final String GET_BYTES_CHARACTER_SET = "UTF-8";

   /*
    * Error message constants
    */
   private static final String TEXT_DECRYPTION_MISMATCH_MESSAGE = "Decrypted text is not the same as original text";

   /**
    * Some key elements.
    *
    * <p>For the sake of repeatable tests the source bytes are constants in this test file.
    * In real use use one <b>must never</b> use values that originate <em>in</em> the program.
    * All source <b>are required</b> to originate from <em>outside</em> the program!</p>
    */
   private static final String SOURCE_TEXT_1 = "The quick brown fox jumped over the lazy dog";
   private static final String SOURCE_TEXT_2 = "314159265358979323846264338327952718281828459045235360287471352722459157718361045473427152204544";
   private static final String SOURCE_TEXT_3 = "The answer to the Ultimate Question of Life, the Universe, and Everything";
   private static byte[] SOURCE_BYTES_1;
   private static byte[] SOURCE_BYTES_2;
   private static byte[] SOURCE_BYTES_3;
   private static final byte[] SOURCE_BYTES_4 = new byte[2_000];
   private static final byte[] NON_RANDOM_SOURCE_BYTES = new byte[100_000];

   /**
    * Known clear text to encrypt
    */
   private static final char[] CLEAR_TEXT_V3 = "This is a clear Text".toCharArray();
   private static final char[] CLEAR_TEXT_V5 = "This#”s?a§StR4nGé€PàS!Wörd9".toCharArray();

   /**
    * Known encrypted text to decrypt
    */
   private static final String ENCRYPTED_TEXT_V3 = "3$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";
   private static final String SUBJECT = "maven_repo_pass";
   private static final String WRONG_SUBJECT = "maven_repo_paxx";
   private static final String ENCRYPTED_TEXT_V5 = "5$Qs6C7prscyK5/OiJRsjWtw$bobPzPN6BJI0Od9pMSUWrSXp5hm/U+0ihzrWH30wMhrZGFPGsnNl/Mv3xJLdHdE03PpD1CW99AK2IZKk006hVA$nP3mG9F4eKvYJoFEiOhMguzMbgpo7XR+JkNJnA6qdhQ";

   /**
    * Known encrypted text to decrypt with invalid HMAC
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_HMAC = "3$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXQ=";

   /**
    * Known encrypted text to decrypt with invalid encryption
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_ENCRYPTION = "3$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1Q$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with invalid IV
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_IV = "3$J/LJT9XGjwfmsKsvHzFefz==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with unknown format id
    */
   private static final String ENCRYPTED_TEXT_WITH_UNKNOWN_FORMAT_ID = "99$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with invalid format id
    */
   private static final String ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID = "Q$J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with missing format id
    */
   private static final String ENCRYPTED_TEXT_WITH_MISSING_FORMAT_ID = "J/LJT9XGjwfmsKsvHzFefQ==$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with empty IV
    */
   private static final String ENCRYPTED_TEXT_WITH_EMPTY_IV = "3$$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Known encrypted text to decrypt with missing IV
    */
   private static final String ENCRYPTED_TEXT_WITH_MISSING_IV = "3$iJIhCFfmzwPVqDwJai30ei5WTpU3/7qhiBS7WbPQCCHJKppD06B2LsRP7tgqh+1g$C9mHKfJi5mdMdIOZWep2GhZl7fNk98c3fBD6j404RXY=";

   /**
    * Checksum error message
    */
   private static final String CHECKSUM_ERROR_MESSAGE = "Checksum does not match data";

   /**
    * Invalid format id error message
    */
   private static final String INVALID_FORMAT_ID_ERROR_MESSAGE = "Invalid format id";


   /** Loop count for tests */
   private static final int TEST_LOOP_COUNT = 100;

   /** One more than the maximum test array size */
   private static final int SUP_TEST_ARRAY_SIZE = 501;

   /*
    * Public methods
    */
   /** Empty constructor */
   public TestSplitKeyEncryption() {
      // Empty constructor.
   }

   /**
    * Create keys and source data before the test
    */
   @BeforeClass
   public static void setUpClass() throws UnsupportedEncodingException {
      /*
       * Create a deterministic HMAC key from a pseudo-random number generator with a fixed key
       */
      // TODO: Do not use this seed constant. Roll your own!!!!
      final Xoroshiro128plusplus xs128 = new Xoroshiro128plusplus(0xEBE770CC82F12283L);

      for (int i = 0; i < COMPUTED_HMAC_KEY.length; i++)
         COMPUTED_HMAC_KEY[i] = xs128.nextByte();

      for (int i = 0; i < SOURCE_BYTES_4.length; i++)
         SOURCE_BYTES_4[i] = xs128.nextByte();

      SOURCE_BYTES_1 = SOURCE_TEXT_1.getBytes(GET_BYTES_CHARACTER_SET);
      SOURCE_BYTES_2 = SOURCE_TEXT_3.getBytes(GET_BYTES_CHARACTER_SET);
      SOURCE_BYTES_3 = SOURCE_TEXT_2.getBytes(GET_BYTES_CHARACTER_SET);

      for (int i = 0; i < NON_RANDOM_SOURCE_BYTES.length; i++)
         NON_RANDOM_SOURCE_BYTES[i] = (byte) (0xff - (i & 0xff));
   }

   /**
    * Delete nonrandom key file after the test
    */
   @AfterClass
   public static void tearDownClass() {
      // No need for class tear down.
   }

   @Before
   public void setUp() {
      // No need for setup.
   }

   @After
   public void tearDown() {
      // No need for tear down
   }

   /*
    * Tests
    */

   /**
    * Test if the encryption of a given byte array is correctly decrypted
    */
   @Test
   public void TestEncryptionDecryptionForByteArray() {
      Random rnd = new Random();

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         for (int i = 0; i < TEST_LOOP_COUNT; i++) {
            final byte[] testByteArray = new byte[rnd.nextInt(SUP_TEST_ARRAY_SIZE)];

            rnd.nextBytes(testByteArray);

            String encryptedText = myEncryptor.encryptData(testByteArray);

            byte[] decryptedByteArray = myEncryptor.decryptDataAsByteArray(encryptedText);

            assertArrayEquals("Decrypted byte array is not the same as original byte array", testByteArray, decryptedByteArray);
         }
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given character array is correctly decrypted
    */
   @Test
   public void TestEncryptionDecryptionForCharacterArray() {
      final char[] testCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         String encryptedText = myEncryptor.encryptData(testCharArray);

         char[] decryptedCharArray = myEncryptor.decryptDataAsCharacterArray(encryptedText);

         assertArrayEquals("Decrypted character array is not the same as original character array", testCharArray, decryptedCharArray);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of a given text is correctly decrypted with a subject present
    */
   @Test
   public void TestEncryptionDecryptionWithSubject() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         String encryptedText = myEncryptor.encryptData(CLEAR_TEXT_V5, SUBJECT);

         char[] decryptedText = myEncryptor.decryptDataAsCharacterArray(encryptedText, SUBJECT);

         assertArrayEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of an empty string is correctly decrypted
    */
   @Test
   public void TestEmptyEncryptionDecryption() {
      final char[] emptyString = "".toCharArray();

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         final String encryptedText = myEncryptor.encryptData(emptyString);

         final char[] decryptedText = myEncryptor.decryptDataAsCharacterArray(encryptedText);

         assertArrayEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, emptyString, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the encryption of an empty string is correctly decrypted with a subject present
    */
   @Test
   public void TestEmptyEncryptionDecryptionWithSubject() {
      final char[] emptyString = "".toCharArray();

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         final String encryptedText = myEncryptor.encryptData(emptyString, SUBJECT);

         final char[] decryptedText = myEncryptor.decryptDataAsCharacterArray(encryptedText, SUBJECT);

         assertArrayEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, emptyString, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a known encrypted text is correctly decrypted
    */
   @Test
   public void TestKnownDecryption() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         char[] decryptedText = myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_V3);

         assertArrayEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, CLEAR_TEXT_V3, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if a given encrypted text is correctly decrypted
    */
   @Test
   public void TestKnownDecryptionWithSubject() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         char[] decryptedText = myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_V5, SUBJECT);

         assertArrayEquals(TEXT_DECRYPTION_MISMATCH_MESSAGE, CLEAR_TEXT_V5, decryptedText);
      } catch (Exception e) {
         e.printStackTrace();
         fail("Exception: " + e.toString());
      }
   }

   /**
    * Test if the decryption of a byte array throws an exception if decrypted as a character array
    */
   @Test
   public void TestDecryptionToCharArrayWithInvalidByteArray() {
      final byte[] testByteArray = new byte[256];

      for (int i = 0; i < testByteArray.length; i++)
         testByteArray[i] = (byte) (0xff - i);

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
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
    * Test if a given encrypted text with the wrong subject throws an exception
    */
   @Test
   public void TestDecryptionWithWrongSubject() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsString(ENCRYPTED_TEXT_V5, WRONG_SUBJECT);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid HMAC throws an exception
    */
   @Test
   public void TestKnownDecryptionWithInvalidHMAC() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_HMAC);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid encryption throws an exception
    */
   @Test
   public void TestKnownDecryptionWithInvalidEncryption() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_ENCRYPTION);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid IV throws an exception
    */
   @Test
   public void TestKnownDecryptionWithInvalidIV() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_IV);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), CHECKSUM_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an unknown format id throws an exception
    */
   @Test
   public void TestKnownDecryptionWithUnknownFormatId() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_UNKNOWN_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Unknown format id", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an invalid format id throws an exception
    */
   @Test
   public void TestKnownDecryptionWithInvalidFormatId() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), INVALID_FORMAT_ID_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with a missing format id throws an exception
    */
   @Test
   public void TestKnownDecryptionWithMissingFormatId() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_MISSING_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), INVALID_FORMAT_ID_ERROR_MESSAGE, e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with an empty IV throws an exception
    */
   @Test
   public void TestKnownDecryptionWithEmptyIV() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_EMPTY_IV);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Number of '$' separated parts in encrypted text is not 4", e.getMessage());
      }
   }

   /**
    * Test if a given encrypted text with a missing IV throws an exception
    */
   @Test
   public void TestKnownDecryptionWithMissingIV() {
      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(CONSTANT_HMAC_KEY, NON_RANDOM_SOURCE_BYTES)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_MISSING_IV);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "Number of '$' separated parts in encrypted text is not 4", e.getMessage());
      }
   }

   /**
    * Test if an empty HMAC throws an exception
    */
   @Test
   public void TestKnownDecryptionWithEmptyHMAC() {
      final byte[] emptyHMAC = new byte[0];

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(emptyHMAC, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "HMAC key length is less than 14", e.getMessage());
      }
   }

   /**
    * Test if a too short HMAC throws an exception
    */
   @Test
   public void TestKnownDecryptionWithShortHMAC() {
      final byte[] shortHMAC = new byte[10];

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(shortHMAC, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "HMAC key length is less than 14", e.getMessage());
      }
   }

   /**
    * Test if a too large HMAC throws an exception
    */
   @Test
   public void TestKnownDecryptionWithTooLargeHMAC() {
      final byte[] largeHMAC = new byte[70];

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(largeHMAC, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "HMAC key length is larger than 32", e.getMessage());
      }
   }

   /**
    * Test if null HMAC key throws an exception
    */
   @Test
   public void TestNullHMACKey() {
      final byte[] aNullHMACKey = null;

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(aNullHMACKey, SOURCE_BYTES_1, SOURCE_BYTES_2, SOURCE_BYTES_3, SOURCE_BYTES_4)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "HMAC key is null", e.getMessage());
      }
   }

   /**
    * Test if one null source byte array throws an exception
    */
   @Test
   public void TestOneNullByteArray() {
      final byte[] aSourceByteArray = null;

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "1. source byte array is null", e.getMessage());
      }
   }

   /**
    * Test if a null source byte array after a non-null byte array throws an exception
    */
   @Test
   public void TestAnotherNullByteArray() {
      final byte[] aSourceByteArray = {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc};
      final byte[] anotherSourceByteArray = null;

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray, anotherSourceByteArray)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "2. source byte array is null", e.getMessage());
      }
   }

   /**
    * Test if a null source byte array after a non-null byte array throws an exception
    */
   @Test
   public void TestZeroLengthByteArray() {
      final byte[] aSourceByteArray = {(byte) 0xaa, (byte) 0xbb, (byte) 0xcc};
      final byte[] anotherSourceByteArray = {};

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray, anotherSourceByteArray)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         assertEquals("Exception: " + e.toString(), "2. source byte array has 0 length", e.getMessage());
      }
   }

   /**
    * Test if a very short source byte array throws an exception
    */
   @Test
   public void TestShortSourceBytes() {
      final byte[] aSourceByteArray = {(byte) 0xAA, (byte) 0xBB, (byte) 0xCC};

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("not enough information provided"));
      }
   }

   /**
    * Test if a uniform source byte array throws an exception
    */
   @Test
   public void TestUniformSourceBytes() {
      final byte[] aSourceByteArray = new byte[300];

      Arrays.fill(aSourceByteArray, (byte) 0xAA);

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("no information provided"));
      }
   }

   /**
    * Test if a nearly uniform source byte array throws an exception
    */
   @Test
   public void TestNearlyUniformSourceBytes() {
      byte[] aSourceByteArray = new byte[100];

      for (int i = 0; i < aSourceByteArray.length; i++) {
         if ((i & 1) != 0)
            aSourceByteArray[i] = (byte) 0x55;
         else
            aSourceByteArray[i] = (byte) 0xAA;
      }

      try (final SplitKeyEncryption myEncryptor = new SplitKeyEncryption(COMPUTED_HMAC_KEY, aSourceByteArray)) {
         myEncryptor.decryptDataAsCharacterArray(ENCRYPTED_TEXT_WITH_INVALID_FORMAT_ID);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String exceptionMessage = e.toString();

         assertTrue("Unexpected exception: " + exceptionMessage, exceptionMessage.contains("at least 129"));
      }
   }
}
