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
 *     2020-02-25: V1.0.0: Created. fhs
 *     2021-09-03: V1.0.1: Corrected wrong comparison. fhs
 */
package de.db.bcm.tupw.strings;

import org.junit.*;

import static org.junit.Assert.*;

/**
 * Test cases for arbitrary tail byte padding
 *
 * @author Frank Schwab
 * @version 1.0.1
 */
public class TestCharacterArrayHelper {

   public TestCharacterArrayHelper() {
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

   @Test
   public void TestFromByteToChar() {
      byte[] originalByteArray = {116, 115, -61, -92, 84, 32, 97, 32, 115, -61, -84, 32, 115, -61, -83, 104, 84};
      byte[] testByteArray = {116, 115, -61, -92, 84, 32, 97, 32, 115, -61, -84, 32, 115, -61, -83, 104, 84};
      char[] correctCharArray = {'t', 's', 'ä', 'T', ' ', 'a', ' ', 's', 'ì', ' ', 's', 'í', 'h', 'T'};

      try {
         char[] charArrayResult = CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(testByteArray);

         assertArrayEquals("Original byte array is changed", originalByteArray, testByteArray);
         assertArrayEquals("Byte array is not correctly converted", correctCharArray, charArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestFromCharToByte() {
      final char[] testCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};
      final char[] originalCharArray = {'T', 'h', 'í', 's', ' ', 'ì', 's', ' ', 'a', ' ', 'T', 'ä', 's', 't'};
      final byte[] correctByteArray = {84, 104, -61, -83, 115, 32, -61, -84, 115, 32, 97, 32, 84, -61, -92, 115, 116};

      try {
         final byte[] byteArrayResult = CharacterArrayHelper.convertCharacterArrayToUTF8ByteArray(testCharArray);

         assertArrayEquals("Original character array is changed", originalCharArray, testCharArray);
         assertArrayEquals("Character array is not correctly converted", correctByteArray, byteArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestNullByteArray() {
      try {
         char[] charArrayResult = CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(null);

         assertNull("Null byte array is not correctly converted", charArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestNullCharArray() {
      try {
         byte[] byteArrayResult = CharacterArrayHelper.convertCharacterArrayToUTF8ByteArray(null);

         assertNull("Null character array is not correctly converted", byteArrayResult);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestEmptyByteArray() {
      try {
         byte[] testByteArray = {};
         char[] charArrayResult = CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(testByteArray);

         assertEquals("Empty byte array is not correctly converted", 0, charArrayResult.length);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestEmptyCharArray() {
      try {
         char[] testCharArray = {};
         byte[] byteArrayResult = CharacterArrayHelper.convertCharacterArrayToUTF8ByteArray(testCharArray);

         assertEquals("Empty character array is not correctly converted", 0, byteArrayResult.length);
      } catch (Exception e) {
         fail("Unexpected exception " + e.toString());
      }
   }

   @Test
   public void TestInvalidByteArray() {
      byte[] testByteArray = {116, 115, -92, -61, 84, 32, 97, 32, 115, -84, -61, 32, 115, -83, -61, 104, 84};

      try {
         CharacterArrayHelper.convertUTF8ByteArrayToCharacterArray(testByteArray);

         fail("Expected exception not thrown");
      } catch (Exception e) {
         final String message = e.toString();

         assertTrue("Unexpected exception " + message, message.contains("MalformedInputException"));
      }
   }
}
