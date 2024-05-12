/*
 * SPDX-FileCopyrightText: 2020-2023 DB Systel GmbH
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
 *     2020-11-13: V1.0.0: Created. fhs
 */
package de.db.bcm.tupw.arrays;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.*;

/**
 * Test cases for Base32 encoding
 *
 * @author Frank Schwab
 * @version 1.0.0
 */

public class TestBase32Encoding {
   static final Random rnd = new Random();

   public TestBase32Encoding() {
   }

   @BeforeClass
   public static void setUpClass() {
   }

   @AfterClass
   public static void tearDownClass() {
   }

   @Before
   public void setUp() {
   }

   @After
   public void tearDown() {
   }

   //******************************************************************
   // Padded RFC 4868 tests
   //******************************************************************

   @Test
   public void TestRandomPaddedEncodeDecode() {
      for (int i = 1; i <= 100; i++) {
         final byte[] testByteArray = new byte[rnd.nextInt(101)];

         rnd.nextBytes(testByteArray);

         String encodedBytes = Base32Encoding.encode(testByteArray);

         final byte[] decodedBytes = Base32Encoding.decode(encodedBytes);

         assertArrayEquals("Decoded byte array is not the same as original byte array", testByteArray, decodedBytes);
      }
   }

   @Test
   public void TestKnownPaddedEncode() {
      byte[] sourceBytes = new byte[0];

      String b32Text = Base32Encoding.encode(sourceBytes);
      assertEquals("Zero length array is not encoded as zero length text", 0, b32Text.length());

      sourceBytes = new byte[] {102};
      b32Text = Base32Encoding.encode(sourceBytes);
      assertEquals("Encoding is not as expected", "MY======", b32Text);

      sourceBytes = new byte[] {102, 111};
      b32Text = Base32Encoding.encode(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXQ====", b32Text);

      sourceBytes = new byte[] {102, 111, 111};
      b32Text = Base32Encoding.encode(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6===", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98};
      b32Text = Base32Encoding.encode(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6YQ=", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97};
      b32Text = Base32Encoding.encode(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6YTB", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97, 114};
      b32Text = Base32Encoding.encode(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6YTBOI======", b32Text);
   }

   @Test
   public void TestKnownPaddedDecode() {
      byte[] decodedBytes = Base32Encoding.decode("");
      assertEquals("Zero length text is not decoded as zero length array", 0, decodedBytes.length);

      decodedBytes = Base32Encoding.decode("MY======");
      byte[] expectedBytes = new byte[] {102};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXQ====");
      expectedBytes = new byte[] {102, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6===");
      expectedBytes = new byte[] {102, 111, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6YQ=");
      expectedBytes = new byte[] {102, 111, 111, 98};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6YTB");
      expectedBytes = new byte[] {102, 111, 111, 98, 97};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6YTBOI======");
      expectedBytes = new byte[] {102, 111, 111, 98, 97, 114};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);
   }

   @Test
   public void TestPaddedNothingEncode() {
      try {
         Base32Encoding.encode(null);

         fail("Expected exception not thrown");
      }
      catch (NullPointerException ex) {
         // This is the expected exception
      }
      catch (Exception ex) {
         fail("Unexpected exception thrown: " + ex.toString());
      }
   }

   @Test
   public void TestPaddedNothingDecode() {
      try {
         Base32Encoding.decode(null);

         fail("Expected exception not thrown");
      }
      catch (NullPointerException ex) {
         // This is the expected exception
      }
      catch (Exception ex) {
         fail("Unexpected exception thrown: " + ex.toString());
      }
   }

   @Test
   public void TestPaddedInvalidLengthsDecode() {
      String[] invalidLengthEncoding = new String[]{"M=======", "MZX=====", "MZXQ===", "MZXW6Y==", "MZXW6YTBO======="};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown on encoding '" + wrongLengthEncoding + "'");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }

   @Test
   public void TestPaddedInvalidCharacterDecode() {
      String[] invalidLengthEncoding = new String[]{"M1======", "MZX~6YTB", "MZXD6YT!", "MZXW6YTBO0======"};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }

   //******************************************************************
   // Unpadded RFC 4868 tests
   //******************************************************************

   @Test
   public void TestHighBytesUnpaddedEncodeDecode() {
      final byte[] testByteArray = new byte[] {(byte) 0xff, (byte) 0xfe, (byte) 0xfc, (byte) 0xa0, (byte) 0x11, (byte) 0x23, (byte) 0x00, (byte) 0xdd, (byte) 0xcc};
      String encodedBytes = Base32Encoding.encodeNoPadding(testByteArray);

      final byte[] decodedBytes = Base32Encoding.decode(encodedBytes);
      assertArrayEquals("Decoded byte array is not the same as original byte array", testByteArray, decodedBytes);
   }

   @Test
   public void TestRandomUnpaddedEncodeDecode() {
      for (int i = 1; i <= 100; i++) {
         final byte[] testByteArray = new byte[rnd.nextInt(101)];

         rnd.nextBytes(testByteArray);

         String encodedBytes = Base32Encoding.encodeNoPadding(testByteArray);

         final byte[] decodedBytes = Base32Encoding.decode(encodedBytes);
         assertArrayEquals("Decoded byte array is not the same as original byte array", testByteArray, decodedBytes);
      }
   }

   @Test
   public void TestKnownUnpaddedEncode() {
      byte[] sourceBytes = new byte[0];

      String b32Text = Base32Encoding.encodeNoPadding(sourceBytes);
      assertEquals("Zero length array is not encoded as zero length text", 0, b32Text.length());

      sourceBytes = new byte[] {102};
      b32Text = Base32Encoding.encodeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "MY", b32Text);

      sourceBytes = new byte[] {102, 111};
      b32Text = Base32Encoding.encodeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXQ", b32Text);

      sourceBytes = new byte[] {102, 111, 111};
      b32Text = Base32Encoding.encodeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98};
      b32Text = Base32Encoding.encodeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6YQ", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97};
      b32Text = Base32Encoding.encodeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6YTB", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97, 114};
      b32Text = Base32Encoding.encodeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "MZXW6YTBOI", b32Text);
   }

   @Test
   public void TestKnownUnpaddedDecode() {
      byte[] decodedBytes = Base32Encoding.decode("MY");
      byte[] expectedBytes = new byte[] {102};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXQ");
      expectedBytes = new byte[] {102, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6");
      expectedBytes = new byte[] {102, 111, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6YQ");
      expectedBytes = new byte[] {102, 111, 111, 98};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6YTB");
      expectedBytes = new byte[] {102, 111, 111, 98, 97};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decode("MZXW6YTBOI");
      expectedBytes = new byte[] {102, 111, 111, 98, 97, 114};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);
   }

   @Test
   public void TestUnpaddedNothingEncode() {
      try {
         Base32Encoding.encodeNoPadding(null);

         fail("Expected exception not thrown");
      }
      catch (NullPointerException ex) {
         // This is the expected exception
      }
      catch (Exception ex) {
         fail("Unexpected exception thrown: " + ex.toString());
      }
   }

   @Test
   public void TestUnpaddedInvalidLengthsDecode() {
      String[] invalidLengthEncoding = new String[]{"M", "MZX", "MZX", "MZXW6Y", "MZXW6YTBO"};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown on encoding '" + wrongLengthEncoding + "'");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }

   @Test
   public void TestUnpaddedInvalidCharacterDecode() {
      String[] invalidLengthEncoding = new String[]{"M1", "MZX~6YT", "MZXD6Y!", "MZXW6YTBO0"};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }

   //******************************************************************
   // Padded spell-safe tests
   //******************************************************************

   @Test
   public void TestRandomPaddedSpellSafeEncodeDecode() {
      for (int i = 1; i <= 100; i++) {
         final byte[] testByteArray = new byte[rnd.nextInt(101)];

         rnd.nextBytes(testByteArray);

         String encodedBytes = Base32Encoding.encodeSpellSafe(testByteArray);

         final byte[] decodedBytes = Base32Encoding.decodeSpellSafe(encodedBytes);
         assertArrayEquals("Decoded byte array is not the same as original byte array", testByteArray, decodedBytes);
      }
   }

   @Test
   public void TestKnownPaddedSpellSafeEncode() {
      byte[] sourceBytes = new byte[0];

      String b32Text = Base32Encoding.encodeSpellSafe(sourceBytes);
      assertEquals("Zero length array is not encoded as zero length text", 0, b32Text.length());

      sourceBytes = new byte[] {102};
      b32Text = Base32Encoding.encodeSpellSafe(sourceBytes);
      assertEquals("Encoding is not as expected", "Jj======", b32Text);

      sourceBytes = new byte[] {102, 111};
      b32Text = Base32Encoding.encodeSpellSafe(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhT====", b32Text);

      sourceBytes = new byte[] {102, 111, 111};
      b32Text = Base32Encoding.encodeSpellSafe(sourceBytes);
      assertEquals("Encoding is not as expected", "Jkhgx===", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98};
      b32Text = Base32Encoding.encodeSpellSafe(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhgxjT=", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97};
      b32Text = Base32Encoding.encodeSpellSafe(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhgxjZ3", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97, 114};
      b32Text = Base32Encoding.encodeSpellSafe(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhgxjZ3NC======", b32Text);
   }

   @Test
   public void TestKnownPaddedSpellSafeDecode() {
      byte[] decodedBytes = Base32Encoding.decodeSpellSafe("");
      assertEquals("Zero length text is not decoded as zero length array", 0, decodedBytes.length);

      decodedBytes = Base32Encoding.decodeSpellSafe("Jj======");
      byte[] expectedBytes = new byte[] {102};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhT====");
      expectedBytes = new byte[] {102, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("Jkhgx===");
      expectedBytes = new byte[] {102, 111, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhgxjT=");
      expectedBytes = new byte[] {102, 111, 111, 98};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhgxjZ3");
      expectedBytes = new byte[] {102, 111, 111, 98, 97};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhgxjZ3NC======");
      expectedBytes = new byte[] {102, 111, 111, 98, 97, 114};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);
   }

   @Test
   public void TestPaddedNothingSpellSafeEncode() {
      try {
         Base32Encoding.encodeSpellSafe(null);

         fail("Expected exception not thrown");
      }
      catch (NullPointerException ex) {
         // This is the expected exception
      }
      catch (Exception ex) {
         fail("Unexpected exception thrown: " + ex.toString());
      }
   }

   @Test
   public void TestPaddedNothingSpellSafeDecode() {
      try {
         Base32Encoding.decodeSpellSafe(null);

         fail("Expected exception not thrown");
      }
      catch (NullPointerException ex) {
         // This is the expected exception
      }
      catch (Exception ex) {
         fail("Unexpected exception thrown: " + ex.toString());
      }
   }

   @Test
   public void TestPaddedInvalidLengthsSpellSafeDecode() {
      String[] invalidLengthEncoding = new String[]{"J=======", "Jjg=====", "Jjgx===", "JjgxhT==", "JjZ3v4c99======="};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown on encoding '" + wrongLengthEncoding + "'");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }

   @Test
   public void TestPaddedInvalidCharacterSpellSafeDecode() {
      String[] invalidLengthEncoding = new String[]{"J1======", "Jkhg~jZ3", "J!hgxjZ3", "JkhgxjZ3N0======"};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }

   //******************************************************************
   // Unpadded spell-safe tests
   //******************************************************************

   @Test
   public void TestRandomUnpaddedSpellSafeEncodeDecode() {
      for (int i = 1; i <= 100; i++) {
         final byte[] testByteArray = new byte[rnd.nextInt(101)];

         rnd.nextBytes(testByteArray);

         String encodedBytes = Base32Encoding.encodeSpellSafeNoPadding(testByteArray);

         final byte[] decodedBytes = Base32Encoding.decodeSpellSafe(encodedBytes);
         assertArrayEquals("Decoded byte array is not the same as original byte array", testByteArray, decodedBytes);
      }
   }

   @Test
   public void TestKnownUnpaddedSpellSafeEncode() {
      byte[] sourceBytes = new byte[0];

      String b32Text = Base32Encoding.encodeSpellSafeNoPadding(sourceBytes);
      assertEquals("Zero length array is not encoded as zero length text", 0, b32Text.length());

      sourceBytes = new byte[] {102};
      b32Text = Base32Encoding.encodeSpellSafeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "Jj", b32Text);

      sourceBytes = new byte[] {102, 111};
      b32Text = Base32Encoding.encodeSpellSafeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhT", b32Text);

      sourceBytes = new byte[] {102, 111, 111};
      b32Text = Base32Encoding.encodeSpellSafeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "Jkhgx", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98};
      b32Text = Base32Encoding.encodeSpellSafeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhgxjT", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97};
      b32Text = Base32Encoding.encodeSpellSafeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhgxjZ3", b32Text);

      sourceBytes = new byte[] {102, 111, 111, 98, 97, 114};
      b32Text = Base32Encoding.encodeSpellSafeNoPadding(sourceBytes);
      assertEquals("Encoding is not as expected", "JkhgxjZ3NC", b32Text);
   }

   @Test
   public void TestKnownUnpaddedSpellSafeDecode() {
      byte[] decodedBytes = Base32Encoding.decodeSpellSafe("");
      assertEquals("Zero length text is not decoded as zero length array", 0, decodedBytes.length);

      decodedBytes = Base32Encoding.decodeSpellSafe("Jj");
      byte[] expectedBytes = new byte[] {102};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhT");
      expectedBytes = new byte[] {102, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("Jkhgx");
      expectedBytes = new byte[] {102, 111, 111};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhgxjT");
      expectedBytes = new byte[] {102, 111, 111, 98};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhgxjZ3");
      expectedBytes = new byte[] {102, 111, 111, 98, 97};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);

      decodedBytes = Base32Encoding.decodeSpellSafe("JkhgxjZ3NC");
      expectedBytes = new byte[] {102, 111, 111, 98, 97, 114};
      assertArrayEquals("Decoded bytes are not as expected", expectedBytes, decodedBytes);
   }

   @Test
   public void TestUnpaddedNothingSpellSafeEncode() {
      try {
         Base32Encoding.encodeSpellSafeNoPadding(null);

         fail("Expected exception not thrown");
      }
      catch (NullPointerException ex) {
         // This is the expected exception
      }
      catch (Exception ex) {
         fail("Unexpected exception thrown: " + ex.toString());
      }
   }

   @Test
   public void TestUnpaddedInvalidLengthsSpellSafeDecode() {
      String[] invalidLengthEncoding = new String[]{"J", "Jjg", "Jjg", "JjgxhT", "JjZ3v4c99"};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown on encoding '" + wrongLengthEncoding + "'");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }

   @Test
   public void TestUnpaddedInvalidCharacterSpellSafeDecode() {
      String[] invalidLengthEncoding = new String[]{"J1", "Jkhg~jZ", "J!hgxjZ", "JkhgxjZ3N0"};

      for (String wrongLengthEncoding : invalidLengthEncoding) {
         try {
            Base32Encoding.decode(wrongLengthEncoding);

            fail("Expected exception not thrown");
         } catch (IllegalArgumentException ex) {
            // This is the expected exception
         } catch (Exception ex) {
            fail("Unexpected exception thrown: " + ex.toString());
         }
      }
   }
}
