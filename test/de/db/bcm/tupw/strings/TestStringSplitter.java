/*
 * SPDX-FileCopyrightText: 2018-2023 DB Systel GmbH
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
 *     2018-12-05: V1.0.0: Created. fhs
 *     2021-09-06: V1.0.1: Refactored empty string tests. fhs
 *     2024-05-10: V1.0.2: Adapted null string tests. fhs
 */
package de.db.bcm.tupw.strings;

import org.junit.*;

import static org.junit.Assert.*;

/**
 * Test cases for string splitter
 *
 * @author Frank Schwab
 * @version 1.0.2
 */
public class TestStringSplitter {

   public TestStringSplitter() {
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
   public void TestNormal() {
      final String[] result = StringSplitter.split("ATestString", "S");

      assertEquals("Split result not of length 2", 2, result.length);
   }

   @Test
   public void TestNullSearchString() {
      final String[] result = StringSplitter.split(null, "S");

      assertEquals("Null search string yields array which has not a length of 1", 1, result.length);
      assertEquals("Null search string yields non-empty result string", "", result[0]);
   }

   @Test
   public void TestFirstElementEmpty() {
      final String[] result = StringSplitter.split("SATestString", "S");

      assertEquals("Split result not of length 3", 3, result.length);
      assertEquals("1. element of split is not empty", 0, result[0].length());
   }

   @Test
   public void TestLastElementEmpty() {
      final String[] result = StringSplitter.split("ATestStringS", "S");

      assertEquals("Split result not of length 3", 3, result.length);
      assertEquals("Last element of split is not empty", 0, result[2].length());
   }

   @Test
   public void TestEmptyStringWithNonEmptyDelimiter() {
      TestEmptyStringVariants("", "/");
   }

   @Test
   public void TestEmptyStringWithEmptyDelimiter() {
      TestEmptyStringVariants("", "");
   }

   @Test
   public void TestEmptyStringWithNullDelimiter() {
      TestEmptyStringVariants("", null);
   }

   @Test
   public void TestNonEmptyStringWithEmptyDelimiter() {
      TestNonEmptyStringVariants("AnotherTest", "");
   }

   @Test
   public void TestNonEmptyStringWithNullDelimiter() {
      TestNonEmptyStringVariants("AnotherTest", null);
   }

   /*
    * Private methods
    */

   private void TestEmptyStringVariants(final String searchString, final String separator) {
      final String[] result = StringSplitter.split(searchString, separator);

      assertEquals("Empty string is not split into array with 1 element", 1, result.length);
      assertEquals("Empty string is not split into array with 1 empty element", "", result[0]);
   }

   private void TestNonEmptyStringVariants(final String searchString, final String separator) {
      final String[] result = StringSplitter.split(searchString, separator);

      assertEquals("Non-empty string is not split into array with 1 element", 1, result.length);
      assertEquals("Non-empty string is not split into original non-empty string", searchString, result[0]);
   }
}
