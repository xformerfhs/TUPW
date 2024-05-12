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
 *     2020-04-29: V1.0.1: Simplified. fhs
 *     2021-09-06: V1.0.2: Corrected SonarLint finding. fhs
 */
package de.db.bcm.tupw.crypto;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Test cases for arbitrary tail byte padding
 *
 * @author Frank Schwab
 * @version 1.0.2
 */
public class TestABytPadding {
   
   /*
    * Private constants
    */
   
   /**
    * Assumed padding block size
    */
   private static final int BLOCK_SIZE = 32;

   /*
    * Test methods
    */

   public TestABytPadding() {
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
   public void TestABytPaddingWorking0DataSize() {
      byte[] unpaddedSourceData = new byte[0];

      TestPadAndUnpad(unpaddedSourceData);
   }

   @Test
   public void TestABytPaddingWorkingSmallerThanBlockSize() {
      byte[] unpaddedSourceData = new byte[BLOCK_SIZE / 4 - 1];

      TestPadAndUnpad(unpaddedSourceData);
   }

   @Test
   public void TestABytPaddingWorkingEqualBlockSize() {
      byte[] unpaddedSourceData = new byte[BLOCK_SIZE];

      TestPadAndUnpad(unpaddedSourceData);
   }

   @Test
   public void TestABytPaddingWorkingGreaterThanBlockSize() {
      byte[] unpaddedSourceData = new byte[BLOCK_SIZE + (BLOCK_SIZE / 2) + 1];

      TestPadAndUnpad(unpaddedSourceData);
   }

   /*
    * Private methods
    */
   private void TestPadAndUnpad(byte[] unpaddedSourceData) {
      byte[] paddedSourceData = ArbitraryTailPadding.addPadding(unpaddedSourceData, BLOCK_SIZE);

      assertTrue("Padded data not longer than unpadded data", paddedSourceData.length > unpaddedSourceData.length);
      assertEquals("Padding length is not multiple of block size: " + paddedSourceData.length, 0, paddedSourceData.length % BLOCK_SIZE);
      assertTrue("Padding is longer than block size", (paddedSourceData.length - unpaddedSourceData.length) <= BLOCK_SIZE);

      byte[] unpaddedPaddedSourceData = ArbitraryTailPadding.removePadding(paddedSourceData);

      assertEquals("Lengths are not the same after padding and unpadding", unpaddedSourceData.length, unpaddedPaddedSourceData.length);
      assertArrayEquals("Data ist not the same after padding and unpadding", unpaddedSourceData,unpaddedPaddedSourceData);
   }
}
