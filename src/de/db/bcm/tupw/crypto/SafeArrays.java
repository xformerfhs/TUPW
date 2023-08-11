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
 *     2018-06-13: V1.0.0: Created. fhs
 *     2018-06-18: V1.0.1: A few more comments and a small optimization. fhs
 *     2018-08-15: V1.0.2: Added a few "finals". fhs
 *     2020-03-23: V1.1.0: Restructured source code according to DBS programming guidelines. fhs
 *     2020-12-04: V1.1.1: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.2.0: Made thread safe. fhs
 */
package de.db.bcm.tupw.crypto;

import java.util.Objects;

/**
 * Implement cryptographically safe array operations
 *
 * @author FrankSchwab
 * @version 1.2.0
 */
public final class SafeArrays {
   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instantiated.</p>
    */
   private SafeArrays() {
      throw new IllegalStateException("Utility class");
   }

   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Constant time byte array compare.
    *
    * <p>This method takes a constant time to compare two byte arrays, i.e. it will
    * take the same time to run if the arrays are equal and if they are not
    * equal. This makes it impossible to attack a cryptographic operation by
    * measuring the time it takes to complete a compare operation.</p>
    *
    * @param a First byte array to compare
    * @param b Second byte array to compare
    * @return {@code true}, if both byte arrays are equal, {@code false}, if not
    */
   public static synchronized boolean constantTimeEquals(final byte[] a, final byte[] b) {
      Objects.requireNonNull(a, "First byte array is null");
      Objects.requireNonNull(b, "Second byte array is null");

      // diff starts with a possible difference in the lengths
      int diff = a.length ^ b.length;

      final int minArrayLength = Math.min(a.length, b.length);

      // Now compare each and every byte with no shortcut and collect differences in diff
      for (int i = 0; i < minArrayLength; i++)
         diff |= a[i] ^ b[i];

      // Diff will only be 0 if bytes and lengths were equal
      return diff == 0;
   }
}
