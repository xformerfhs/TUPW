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
 *     2020-02-26: V1.0.0: Created. fhs
 */
package de.xformerfhs.crypto;

import org.junit.*;

import javax.crypto.Cipher;

import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

/**
 * Test case for Java JCE maximum key length
 *
 * @author Frank Schwab
 * @version 1.0.0
 */
public class TestJCECryptoStrength {

   /*
    * Private constants
    */
   public TestJCECryptoStrength() {
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
   public void TestCryptoPolicy() throws NoSuchAlgorithmException {
      int maxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
      assertTrue("Maximum allowed AES key length is " + maxKeyLength + " which is less than the required key length of 256. Please use a JDK where strong encryption is enabled or use a strong encryption jurisdiction policy file",
                 maxKeyLength >= 256);
   }
}
