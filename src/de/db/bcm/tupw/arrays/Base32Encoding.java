/*
 * SPDX-FileCopyrightText: 2020-2023 DB Systel GmbH
 * SPDX-FileCopyrightText: 2023 Frank Schwab
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * You may not use this file except in compliance with the License.
 *
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
 * Version: 1.3.1
 *
 * Change history:
 *    2020-11-12: V1.0.0: Created. fhs
 *    2020-11-20: V1.1.0: Added interface methods with existing buffers. fhs
 *    2020-12-04: V1.1.1: Corrected several SonarLint findings. fhs
 *    2020-12-29: V1.2.0: Made thread safe. fhs
 *    2021-05-17: V1.3.0: Simplified byte to char mapping. fhs
 *    2022-02-15: V1.3.1: Added some Finals. fhs
 */

package de.db.bcm.tupw.arrays;

import java.util.Arrays;
import java.util.Objects;

/**
 * Converts byte arrays from and to Base32 encoding either, as specified in RFC4868, or in spell-safe format.
 *
 * @author Frank Schwab
 * @version 1.3.1
 */

public class Base32Encoding {
   //******************************************************************
   // Private constants
   //******************************************************************

   // Error messages
   private static final String ERROR_TEXT_INVALID_CHARACTER     = "Character is not a valid Base32 character";
   private static final String ERROR_TEXT_INVALID_STRING_LENGTH = "Invalid Base32 string length";
   private static final String ERROR_TEXT_DESTINATION_TOO_SMALL = "DestinationBuffer is too small";

   // Processing constants
   private static final byte BITS_PER_CHARACTER = 5;
   private static final byte BITS_PER_BYTE = 8;
   private static final byte BITS_DIFFERENCE = BITS_PER_BYTE - BITS_PER_CHARACTER;
   private static final byte INVALID_CHARACTER_VALUE = -1;
   private static final int  BYTE_MASK = 255;
   private static final int  CHARACTER_MASK = 31;
   private static final char PADDING_CHARACTER = '=';
   private static final int  CODEPOINT_ZERO = 48;

   // Mapping tables

   // RFC 4648

   /*
    * This is the RFC 4648 mapping:
    *
    * Value      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
    * Character  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O  P  Q  R  S  T  U  V  W  X  Y  Z  2  3  4  5  6  7
    */

   /**
    * Mapping from a byte value to an RFC 4648 Base32 character
    */
   private static final char[] RFC_4648_VALUE_TO_CHAR = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
         'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
         'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
         'Y', 'Z', '2', '3', '4', '5', '6', '7'};

   /**
    * Mapping from an RFC 4648 Base32 character to byte value ('0'-based)
    */
   private static final byte[] RFC_4648_CHAR_TO_VALUE = {-1, -1, 26, 27, 28, 29, 30, 31,
         -1, -1, -1, -1, -1, -1, -1, -1,
         -1, 0, 1, 2, 3, 4, 5, 6,
         7, 8, 9, 10, 11, 12, 13, 14,
         15, 16, 17, 18, 19, 20, 21, 22,
         23, 24, 25, -1, -1, -1, -1, -1,
         -1, 0, 1, 2, 3, 4, 5, 6,
         7, 8, 9, 10, 11, 12, 13, 14,
         15, 16, 17, 18, 19, 20, 21, 22,
         23, 24, 25};

   // Spell-safe

   /*
    * This is the spell-safe mapping:
    *
    * Value      0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
    * Character  2  3  4  5  6  7  8  9  C  D  G  H  J  K  N  P  T  V  X  Z  c  d  g  h  j  k  n  p  t  v  x  z
    *
    * The mapping is constructed so that there are no vowels, no B that can be confused with 8,
    * no S that can be confused with 5, no O or Q that can be confused with 0,
    * no 1, I and L that can be confused with each other, no R that can be confused with P and
    * no U and W that can be confused with each other and with V.
    */

   /**
    * Mapping from a byte value to a spell-safe Base32 character
    */
   private static final char[] SPELL_SAFE_VALUE_TO_CHAR = {'2', '3', '4', '5', '6', '7', '8', '9',
         'C', 'D', 'G', 'H', 'J', 'K', 'N', 'P',
         'T', 'V', 'X', 'Z', 'c', 'd', 'g', 'h',
         'j', 'k', 'n', 'p', 't', 'v', 'x', 'z'};

   /**
    * Mapping from a spell-safe Base32 character to byte value ('0'-based)
    */
   private static final byte[] SPELL_SAFE_CHAR_TO_VALUE = {-1, -1, 0, 1, 2, 3, 4, 5,
         6, 7, -1, -1, -1, -1, -1, -1,
         -1, -1, -1, 8, 9, -1, -1, 10,
         11, -1, 12, 13, -1, -1, 14, -1,
         15, -1, -1, -1, 16, -1, 17, -1,
         18, -1, 19, -1, -1, -1, -1, -1,
         -1, -1, -1, 20, 21, -1, -1, 22,
         23, -1, 24, 25, -1, -1, 26, -1,
         27, -1, -1, -1, 28, -1, 29, -1,
         30, -1, 31};


   //******************************************************************
   // Constructor
   //******************************************************************

   /**
    * Private constructor
    *
    * <p>This class is not meant to be instantiated.</p>
    */
   private Base32Encoding() {
      throw new IllegalStateException("This class is not meant to be instantiated");
   }


   //******************************************************************
   // Public methods
   //******************************************************************

   // Decode methods

   /**
    * Decodes a Base32 string into a new byte array
    *
    * @param encodedValue The Base32 string to decode
    * @return The decoded Base32 string as a byte array
    */
   public static synchronized byte[] decode(final String encodedValue) {
      return decodeNewBufferWithMapping(encodedValue, RFC_4648_CHAR_TO_VALUE);
   }

   /**
    * Decodes a Base32 string into an existing byte array
    *
    * @param encodedValue The Base32 string to decode
    * @param destinationBuffer Byte array where the decoded values are placed
    * @return The length of the bytes written into the destination buffer
    */
   public static synchronized int decode(final String encodedValue, final byte[] destinationBuffer) {
      return decodeExistingBufferWithMapping(encodedValue, destinationBuffer, RFC_4648_CHAR_TO_VALUE);
   }

   /**
    * Decodes a spell-safe Base32 string into a new byte array
    *
    * @param encodedValue The Base32 string to decode
    * @return The decoded spell-safe Base32 string as a byte array
    */
   public static synchronized byte[] decodeSpellSafe(final String encodedValue) {
      return decodeNewBufferWithMapping(encodedValue, SPELL_SAFE_CHAR_TO_VALUE);
   }

   /**
    * Decodes a spell-safe Base32 string into an existing byte array
    *
    * @param encodedValue The Base32 string to decode
    * @param destinationBuffer Byte array where the decoded values are placed
    * @return The length of the bytes written into the destination buffer
    */
   public static synchronized int decodeSpellSafe(final String encodedValue, final byte[] destinationBuffer) {
      return decodeExistingBufferWithMapping(encodedValue, destinationBuffer, SPELL_SAFE_CHAR_TO_VALUE);
   }

   // Encode methods

   /**
    * Encodes a byte array into a padded Base32 string
    *
    * @param aByteArray The byte array to encode
    * @return The Base32 representation of the bytes in {@code aByteArray}
    */
   public static synchronized String encode(final byte[] aByteArray) {
      return encodeWorker(aByteArray, RFC_4648_VALUE_TO_CHAR, true);
   }

   /**
    * Encodes a byte array into an unpadded Base32 string
    *
    * @param aByteArray The byte array to encode
    * @return The Base32 representation of the bytes in {@code aByteArray}
    */
   public static synchronized String encodeNoPadding(final byte[] aByteArray) {
      return encodeWorker(aByteArray, RFC_4648_VALUE_TO_CHAR, false);
   }

   /**
    * Encodes a byte array into a padded spell-safe Base32 string
    *
    * @param aByteArray The byte array to encode
    * @return The spell-safe Base32 representation of the bytes in {@code aByteArray}
    */
   public static synchronized String encodeSpellSafe(final byte[] aByteArray) {
      return encodeWorker(aByteArray, SPELL_SAFE_VALUE_TO_CHAR, true);
   }

   /**
    * Encodes a byte array into an unpadded spell-safe Base32 string
    *
    * @param aByteArray The byte array to encode
    * @return The spell-safe Base32 representation of the bytes in {@code aByteArray}
    */
   public static synchronized String encodeSpellSafeNoPadding(final byte[] aByteArray) {
      return encodeWorker(aByteArray, SPELL_SAFE_VALUE_TO_CHAR, false);
   }

   //******************************************************************
   // Private methods
   //******************************************************************

   // Internal encode and decode methods
   // Decode methods

   /**
    * Decode an encoded value to a new byte array with a specified mapping
    *
    * @param encodedValue Encoded value to decode
    * @param mapCharToByte Mapping table to use
    * @return Newly created byte array with the decoded bytes
    */
   private static byte[] decodeNewBufferWithMapping(final String encodedValue, final byte[] mapCharToByte) {
      final int byteCount = checkEncodedValue(encodedValue);

      final byte[] result = new byte[byteCount];

      if (byteCount > 0)
         decodeWorker(encodedValue, result, byteCount, mapCharToByte);

      return result;
   }

   /**
    * Decode an encoded value to an existing byte array with a specified mapping
    *
    * @param encodedValue Encoded value to decode
    * @param destinationBuffer Byte array where the decoded values are placed
    * @param mapCharToByte Mapping table to use
    * @return Number of bytes in the {@code destinationBuffer} that are filled
    */
   private static int decodeExistingBufferWithMapping(final String encodedValue,
                                                      final byte[] destinationBuffer,
                                                      final byte[] mapCharToByte) {
      final int byteCount = checkEncodedValue(encodedValue);

      if (byteCount <= destinationBuffer.length) {
         if (byteCount > 0)
            decodeWorker(encodedValue, destinationBuffer, byteCount, mapCharToByte);

         return byteCount;
      }
      else
         throw new IllegalArgumentException(ERROR_TEXT_DESTINATION_TOO_SMALL);
   }

   /**
    * Decodes a Base32 string into a byte array
    *
    * @param encodedValue  The Base32 string to decode
    * @param destinationBuffer Byte array where the result is placed
    * @param byteCount No. of bytes to be placed in {@code destinationBuffer}
    * @param mapCharToByte Array with mappings from the character to the corresponding byte
    */
   private static void decodeWorker(final String encodedValue,
                                    final byte[] destinationBuffer,
                                    final int byteCount,
                                    final byte[] mapCharToByte) {
      byte actByte = 0;
      byte bitsRemaining = BITS_PER_BYTE;
      byte mask;
      int arrayIndex = 0;

      for (int i = 0; i < encodedValue.length(); i++) {
         final char encodedChar = encodedValue.charAt(i);

         if (encodedChar == PADDING_CHARACTER)
            break;

         final byte charValue = charToValue(encodedChar, mapCharToByte);

         if (bitsRemaining > BITS_PER_CHARACTER) {
            mask = (byte) (charValue << (bitsRemaining - BITS_PER_CHARACTER));
            actByte |= mask;
            bitsRemaining -= BITS_PER_CHARACTER;
         } else {
            mask = (byte) (charValue >>> (BITS_PER_CHARACTER - bitsRemaining));
            actByte |= mask;
            destinationBuffer[arrayIndex] = actByte;
            arrayIndex++;
            bitsRemaining += BITS_DIFFERENCE;

            if (bitsRemaining < BITS_PER_BYTE)
               actByte = (byte) (charValue << bitsRemaining);
            else
               actByte = 0;
         }
      }

      // If we did not end with a full byte, write the remainder
      if (arrayIndex < byteCount)
         destinationBuffer[arrayIndex] = actByte;
   }

   // Encode methods

   /**
    * Encodes a byte array into a Base32 string
    *
    * @param aByteArray    The byte array to encode
    * @param mapByteToChar Array with mappings from the byte to the corresponding character
    * @param withPadding {@code True}: Result will be padded, {@code False}: Result will not be padded
    * @return The Base32 representation of the bytes in {@code aByteArray}
    */
   private static String encodeWorker(final byte[] aByteArray, final char[] mapByteToChar, final boolean withPadding) {
      final int[] lastIndex = new int[1];   // Since Java can not return a value in a call parameter we need to specify this as an array
      final char[] resultArray = encodeInternal(aByteArray, lastIndex, mapByteToChar);

      if (withPadding) {
         Arrays.fill(resultArray, lastIndex[0], resultArray.length, PADDING_CHARACTER);
         lastIndex[0] = resultArray.length;
      }

      final String result = new String(resultArray, 0, lastIndex[0]);

      ArrayHelper.clear(resultArray);

      return result;
   }

   /**
    * Encodes a byte array into Base32 character array
    *
    * @param aByteArray    The byte array to encode
    * @param lastIndex     The last index to use. This is a return value!
    * @param mapByteToChar Array with mappings from the byte to the corresponding character
    * @return The encoded bytes as a character array
    */
   private static char[] encodeInternal(final byte[] aByteArray, final int[] lastIndex, final char[] mapByteToChar) {
      Objects.requireNonNull(aByteArray, "aByteArray must not be null");

      if (aByteArray.length > 0) {
         final int charCount = (int) (Math.ceil((double) aByteArray.length / BITS_PER_CHARACTER) * BITS_PER_BYTE);

         final char[] result = new char[charCount];

         byte actValue = 0;
         byte bitsRemaining = BITS_PER_CHARACTER;
         int arrayIndex = 0;

         for (byte b : aByteArray) {
            final int bNoSignExtension = b & BYTE_MASK;   // This stupid Java implicit sign extended conversion to int!!!!

            actValue |= (byte) (bNoSignExtension >>> (BITS_PER_BYTE - bitsRemaining));
            result[arrayIndex] = mapByteToChar[actValue];
            arrayIndex++;

            if (bitsRemaining <= BITS_DIFFERENCE) {
               actValue = (byte) ((byte) (bNoSignExtension >>> (BITS_DIFFERENCE - bitsRemaining)) & CHARACTER_MASK);
               result[arrayIndex] = mapByteToChar[actValue];
               arrayIndex++;
               bitsRemaining += BITS_PER_CHARACTER;
            }

            bitsRemaining -= BITS_DIFFERENCE;
            actValue = (byte) ((bNoSignExtension << bitsRemaining) & CHARACTER_MASK);
         }

         // If we did not end with a full char
         if (arrayIndex < charCount) {
            result[arrayIndex] = mapByteToChar[actValue];
            arrayIndex++;
         }

         lastIndex[0] = arrayIndex;

         return result;
      } else {
         lastIndex[0] = 0;
         return new char[0];
      }
   }

   // Mapping methods

   /**
    * Maps a character to the corresponding byte value
    *
    * @param c Character to map
    * @param mapCharToByte Map array
    * @return Value corresponding to character {@code c}
    */
   private static byte charToValue(final char c, final byte[] mapCharToByte) {
      final int index = c - CODEPOINT_ZERO;

      if ((index >= 0) && (index < mapCharToByte.length)) {
         final byte result = mapCharToByte[index];

         if (result != INVALID_CHARACTER_VALUE)
            return result;
         else
            throw new IllegalArgumentException(ERROR_TEXT_INVALID_CHARACTER);
      } else
         throw new IllegalArgumentException(ERROR_TEXT_INVALID_CHARACTER);
   }

   // Length helper methods

   /**
    * Checks if {@code encodedValue} has a valid length and returns it, if it has one
    *
    * @param encodedValue The encoded value to check
    * @return The number of decoded bytes in the encoded value
    */
   private static int checkEncodedValue(final String encodedValue) {
      Objects.requireNonNull(encodedValue, "encodedValue must not be null");

      final int lengthWithoutPadding = lengthWithoutTrailingChar(encodedValue, PADDING_CHARACTER);

      if (lengthWithoutPadding > 0)
         if (isLengthValid(encodedValue.length(), lengthWithoutPadding))
            return (lengthWithoutPadding * BITS_PER_CHARACTER) / BITS_PER_BYTE;
         else
            throw new IllegalArgumentException(ERROR_TEXT_INVALID_STRING_LENGTH);
      else
         return 0;
   }

   /**
    * Gets length of string without counting a trailing character
    *
    * @param sourceString String to get the length for
    * @param trailingChar Trailing character to ignore
    * @return Length of {@code sourceString} without counting {@code trailingChar} at the end
    */
   private static int lengthWithoutTrailingChar(final String sourceString, final char trailingChar) {
      for (int i = sourceString.length() - 1; i >= 0; i--) {
         if (sourceString.charAt(i) != trailingChar)
            return i + 1;
      }

      // Only padding characters found or length is 0
      return 0;
   }

   /**
    * Tests if data length is valid for a Base32 string
    *
    * @param dataLength           Total length of Base32 string
    * @param lengthWithoutPadding Length of data without padding in Base32 string
    * @return {@code True}: Length is valid, {@code False}: Length is invalid
    */
   private static boolean isLengthValid(final int dataLength, final int lengthWithoutPadding) {
      final int lastLength = lengthWithoutPadding % BITS_PER_BYTE;

      // 1/3/6 are invalid lengths of the last block
      if ((lastLength == 1) || (lastLength == 3) || (lastLength == 6))
         return false;
      else
      if (dataLength != lengthWithoutPadding)
         return (dataLength % BITS_PER_BYTE) == 0;
      else
         return true;
   }
}
