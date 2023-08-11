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
 */
package de.db.bcm.tupw.numbers;

import org.junit.*;

import java.util.Date;

import static org.junit.Assert.*;


/**
 * Test cases for Pseudo-random numebr generators
 *
 * @author Frank Schwab
 * @version 1.0.0
 */
public class TestPRNG {
   //
   // The following numbers are taken from https://commons.apache.org/proper/commons-rng/xref-test/org/apache/commons/rng/core/source64/SplitMix64Test.html .
   //
   final long SM64_SEED = 0x1a2b3c4d5e6f7531L;

   final long[] SM64_EXPECTED_SEQUENCE = {
            0x4141302768c9e9d0L, 0x64df48c4eab51b1aL, 0x4e723b53dbd901b3L, 0xead8394409dd6454L,
            0x3ef60e485b412a0aL, 0xb2a23aee63aecf38L, 0x6cc3b8933c4fa332L, 0x9c9e75e031e6fccbL,
            0x0fddffb161c9f30fL, 0x2d1d75d4e75c12a3L, 0xcdcf9d2dde66da2eL, 0x278ba7d1d142cfecL,
            0x4ca423e66072e606L, 0x8f2c3c46ebc70bb7L, 0xc9def3b1eeae3e21L, 0x8e06670cd3e98bceL,
            0x2326dee7dd34747fL, 0x3c8fff64392bb3c1L, 0xfc6aa1ebe7916578L, 0x3191fb6113694e70L,
            0x3453605f6544dac6L, 0x86cf93e5cdf81801L, 0x0d764d7e59f724dfL, 0xae1dfb943ebf8659L,
            0x012de1babb3c4104L, 0xa5a818b8fc5aa503L, 0xb124ea2b701f4993L, 0x18e0374933d8c782L,
            0x2af8df668d68ad55L, 0x76e56f59daa06243L, 0xf58c016f0f01e30fL, 0x8eeafa41683dbbf4L,
            0x7bf121347c06677fL, 0x4fd0c88d25db5ccbL, 0x99af3be9ebe0a272L, 0x94f2b33b74d0bdcbL,
            0x24b5d9d7a00a3140L, 0x79d983d781a34a3cL, 0x582e4a84d595f5ecL, 0x7316fe8b0f606d20L,
   };


   //
   // The following numbers are taken from https://commons.apache.org/proper/commons-rng/xref-test/org/apache/commons/rng/core/source64/XoRoShiRo128PlusPlusTest.html .
   //
   private final static long[] XS128_SEED = {
            0x12DE1BABB3C4104L, 0xA5A818B8FC5AA503L
   };

   private final static long[] XS128_EXPECTED_SEQUENCE = {
            0xF61550E8874B8EAFL, 0x125015FCE911E8F6L, 0xFF0E6030E39AF1A4L, 0xD5738FC2A502673BL,
            0xEF48CDCBEFD84325L, 0xB60462C014133DA1L, 0xA62C6D8B9F87CD81L, 0x52FD609A347198EBL,
            0x3C717475E803BF09L, 0x1B6E66B21504A677L, 0x528F64243DB486F4L, 0x3676015C33FBF0FAL,
            0x3E05F2EA0216A127L, 0x373343BB4159FA59L, 0xC375C54EBE2F9097L, 0x52D85B22744E0574L,
            0x55DD7E34E687524L, 0xB749AFC4BC4ED98AL, 0x31B972F93D117746L, 0xC0E13329779ABC15L,
            0xEE52EC4B4DDC0091L, 0xC756C7DD1D6796D6L, 0x3CE47F42E211C63EL, 0xA635AA7CE5D06101L,
            0xE8054178CBB492C1L, 0x3CC3AD122E7DA816L, 0xCBAD73CDACAB8FDL, 0x20AA1CBC64638B31L,
            0x3BCE572CFE3BC776L, 0xCC81E41637090CD8L, 0x69CC93E599F51181L, 0x2D5C9A4E509F984DL,
            0xF4F3BF08FF627F92L, 0x3430E0A0E8670235L, 0x75A856B68968F466L, 0xDEE1DBBB374913D7L,
            0x9736E33202FBE05BL, 0x4BEA0CC1151902A4L, 0x9FE7FD9D8DE47D13L, 0xF011332584A1C7ABL
   };

   /*
    * Class variables
    */
   private static Xoroshiro128plusplus m_Xs128;
   private static SplitMix64 m_Sm64;

   /*
    * Private constants
    */

   private static final int TEST_SIZE = 97;
   private static final int TEST_START = 17;
   private static final int TEST_END = TEST_START + TEST_SIZE - 1;
   private static final int TEST_ITERATIONS = 1000;

   public TestPRNG() {
   }

   @BeforeClass
   public static void setUpClass() {
      final Date now = new Date();
      long timeMilli = now.getTime();

      m_Xs128 = new Xoroshiro128plusplus(timeMilli);

      timeMilli = now.getTime();
      m_Sm64 = new SplitMix64(timeMilli);
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
   public void TestXs128ExpectedSequence() {
      Xoroshiro128plusplus xs128 = new Xoroshiro128plusplus(XS128_SEED);

      long[] result = new long[XS128_EXPECTED_SEQUENCE.length];

      for (int i = 0; i < XS128_EXPECTED_SEQUENCE.length; i++)
         result[i] = xs128.nextLong();

      assertArrayEquals("XS128pp does not produce expected sequence of numbers", XS128_EXPECTED_SEQUENCE, result);
   }

   @Test
   public void TestXs128Long() {
      final long[] checkLong = new long[TEST_SIZE];
      long r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextLong(TEST_START, TEST_END);
         checkLong[(int) (r - TEST_START)]++;
      }

      for (int i = 0; i < checkLong.length; i++)
         assertNotEquals("Xs128: Long value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkLong[i]);
   }

   @Test
   public void TestXs128Int() {
      final int[] checkInt = new int[TEST_SIZE];
      int r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextInt(TEST_START, TEST_END);
         checkInt[r - TEST_START]++;
      }

      for (int i = 0; i < checkInt.length; i++)
         assertNotEquals("Xs128: Int value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkInt[i]);
   }

   @Test
   public void TestXs128Short() {
      final short[] checkShort = new short[TEST_SIZE];
      short r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextShort((short) TEST_START, (short) TEST_END);
         checkShort[r - TEST_START]++;
      }

      for (int i = 0; i < checkShort.length; i++)
         assertNotEquals("Xs128: Short value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkShort[i]);
   }

   @Test
   public void TestXs128Byte() {
      final byte[] checkByte = new byte[TEST_SIZE];
      byte r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Xs128.nextByte((byte) TEST_START, (byte) TEST_END);
         checkByte[r - TEST_START]++;
      }

      for (int i = 0; i < checkByte.length; i++)
         assertNotEquals("Xs128: Byte value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkByte[i]);
   }

   @Test
   public void TestSm64ExpectedSequence() {
      SplitMix64 sm64 = new SplitMix64(SM64_SEED);

      long[] result = new long[SM64_EXPECTED_SEQUENCE.length];

      for (int i = 0; i < SM64_EXPECTED_SEQUENCE.length; i++)
         result[i] = sm64.nextLong();

      assertArrayEquals("Sm64 does not produce expected sequence of numbers", SM64_EXPECTED_SEQUENCE, result);
   }

   @Test
   public void TestSm64Long() {
      final long[] checkLong = new long[TEST_SIZE];
      long r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextLong(TEST_START, TEST_END);
         checkLong[(int) (r - TEST_START)]++;
      }

      for (int i = 0; i < checkLong.length; i++)
         assertNotEquals("Sm64: Long value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkLong[i]);
   }

   @Test
   public void TestSm64Int() {
      final int[] checkInt = new int[TEST_SIZE];
      int r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextInt(TEST_START, TEST_END);
         checkInt[r - TEST_START]++;
      }

      for (int i = 0; i < checkInt.length; i++)
         assertNotEquals("Sm64: Int value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkInt[i]);
   }

   @Test
   public void TestSm64Short() {
      final short[] checkShort = new short[TEST_SIZE];
      short r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextShort((short) TEST_START, (short) TEST_END);
         checkShort[r - TEST_START]++;
      }

      for (int i = 0; i < checkShort.length; i++)
         assertNotEquals("Sm64: Short value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkShort[i]);
   }

   @Test
   public void TestSm64Byte() {
      final byte[] checkByte = new byte[TEST_SIZE];
      byte r;

      for (int i = 1; i <= TEST_ITERATIONS; i++) {
         r = m_Sm64.nextByte((byte) TEST_START, (byte) TEST_END);
         checkByte[r - TEST_START]++;
      }

      for (int i = 0; i < checkByte.length; i++)
         assertNotEquals("Sm64: Byte value " + (TEST_START + i) + " was not generated at all in " + TEST_ITERATIONS + " iterations", 0, checkByte[i]);
   }
}
