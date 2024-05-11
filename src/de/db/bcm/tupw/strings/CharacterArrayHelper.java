/*
 * SPDX-FileCopyrightText: 2020-2023 DB Systel GmbH
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
 *     2020-03-25: V1.0.0: Created. fhs
 *     2020-03-27: V1.0.1: Only catch the expected checked exception in method convertCharacterArrayToUTF8ByteArray. fhs
 *     2020-12-04: V1.0.2: Corrected several SonarLint findings. fhs
 *     2020-12-29: V1.1.0: Made thread safe. fhs
 */
package de.db.bcm.tupw.strings;

import de.db.bcm.tupw.arrays.ArrayHelper;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;
import java.util.Arrays;

/**
 * Class to convert between character and byte arrays
 *
 * <p>This is a class that should not exist. Java ought to have a method {@code ByteArray.toCharArray(CharSet)} and vice versa.
 * Unfortunately Java does not have it and there is absolutely no easy way to convert between character
 * and byte arrays. One has to use this complicated, unintuitive and strange buffer conversion stuff implemented here.</p>
 *
 * @author FrankSchwab
 * @version 1.1.0
 */
public class CharacterArrayHelper {
   //******************************************************************
   // Class variables
   //******************************************************************
   private static final CharsetDecoder UTF8_DECODER = StandardCharsets.UTF_8.newDecoder();
   private static final CharsetEncoder UTF8_ENCODER = StandardCharsets.UTF_8.newEncoder();


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instanced.</p>
    */
   private CharacterArrayHelper() {
      throw new IllegalStateException("This class is not meant to be instanced");
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   /**
    * Convert a character array into a UTF-8 encoded byte array
    *
    * @param sourceCharacterArray character array to encode
    * @return UTF-8 encoded byte array of the characters in {@code sourceCharacterArray}
    */
   public static synchronized byte[] convertCharacterArrayToUTF8ByteArray(final char[] sourceCharacterArray) {
      byte[] result = null;

      if (sourceCharacterArray != null) {
         final CharBuffer tempCharBuffer = CharBuffer.wrap(sourceCharacterArray);

         ByteBuffer tempByteBuffer = null;

         try {
            tempByteBuffer = UTF8_ENCODER.encode(tempCharBuffer);
         } catch (CharacterCodingException e) {
            // As UTF-8 can always encode *every* Unicode character a CharacterCodingException exception can never happen.
            // With this try-catch-statement the unnecessary declaration of "throws CharacterCodingException"
            // in the method signature is suppressed.
         }

         // tempByteBuffer is guaranteed not be null here
         // The encode method above can only throw runtime exceptions
         // In this case we will not get here
         // If we get here there was no runtime exception and tempByteBuffer is not null
         result = Arrays.copyOf(tempByteBuffer.array(), tempByteBuffer.limit());

         ArrayHelper.clear(tempByteBuffer.array());
      }

      return result;
   }

   /**
    * Convert a UTF-8 encoded byte array into a character array
    *
    * @param sourceByteArray (Hopefully) UTF-8 encoded byte array
    * @return Character array from the UTF-8 encoded {@code sourceByteArray}
    * @throws CharacterCodingException if a byte sequence is malformed
    */
   public static synchronized char[] convertUTF8ByteArrayToCharacterArray(final byte[] sourceByteArray) throws CharacterCodingException {
      char[] result = null;

      if (sourceByteArray != null) {
         final ByteBuffer tempByteBuffer = ByteBuffer.wrap(sourceByteArray);
         final CharBuffer tempCharBuffer = UTF8_DECODER.decode(tempByteBuffer);

         result = Arrays.copyOf(tempCharBuffer.array(), tempCharBuffer.limit());
         ArrayHelper.clear(tempCharBuffer.array());
      }

      return result;
   }
}
