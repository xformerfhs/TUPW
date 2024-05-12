/*
 * SPDX-FileCopyrightText: 2018-2023 DB Systel GmbH
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
 *     2018-08-16: V1.0.0: Created. fhs
 *     2020-04-27: V1.0.1: Corrected some typos. fhs
 */
package de.db.bcm.tupw.crypto;

import org.junit.*;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.Assert.*;

/**
 * Test cases for ByteArrayBlinding
 *
 * @author Frank Schwab
 * @version 1.0.1
 */
public class TestByteArrayBlinding {

   /*
    * Private constants
    */
   public TestByteArrayBlinding() {
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
   public void TestBlinding() {
      final Random rng = new Random();

      final byte[] data0 = new byte[0];
      rng.nextBytes(data0);

      byte[] blindedData = ByteArrayBlinding.buildBlindedByteArray(data0, 17);
      byte[] unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data0.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data0.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data0, unblindedData);

      final byte[] data1 = new byte[1];
      rng.nextBytes(data1);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data1, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data1.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data1.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data1, unblindedData);

      final byte[] data2 = new byte[16];
      rng.nextBytes(data2);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data2, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data2.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data2.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data2, unblindedData);

      final byte[] data3 = new byte[20];
      rng.nextBytes(data3);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data3, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data3.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data3.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data3, unblindedData);

      final byte[] data4 = new byte[18000];
      rng.nextBytes(data4);

      blindedData = ByteArrayBlinding.buildBlindedByteArray(data4, 17);
      unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

      assertTrue("Blinded data not longer than source data", blindedData.length > data4.length);
      assertEquals("Lengths are not the same after blinding and unblinding", data4.length, unblindedData.length);
      assertArrayEquals("Data is not the same after blinding and unblinding", data4, unblindedData);
   }

   @Test
   public void TestBlindingLoop() {
      SecureRandom rng = SecureRandomFactory.getSensibleInstance();

      byte[] blindedData;
      byte[] unblindedData;

      int minimumLength;

      for (int dataSize = 1; dataSize <= 50; dataSize++) {
         byte[] data1 = new byte[dataSize];
         rng.nextBytes(data1);

         for (int i = 0; i < 256; i++) {
            minimumLength = rng.nextInt(65);

            blindedData = ByteArrayBlinding.buildBlindedByteArray(data1, minimumLength);
            unblindedData = ByteArrayBlinding.unBlindByteArray(blindedData);

            assertArrayEquals("Data is not the same after blinding and unblinding", data1, unblindedData);
         }
      }
   }
}
