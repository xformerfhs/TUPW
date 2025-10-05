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
 *     2020-03-19: V1.0.0: Created. fhs
 *     2021-09-01: V1.0.1: Added serialVersionUID. fhs
 */
package de.xformerfhs.crypto;

import java.io.Serial;

/**
 * Exception to indicate that some parameter to a cryptographic method is invalid.
 *
 * @author FrankSchwab
 * @version 1.0.1
 */
public class InvalidCryptoParameterException extends Exception {
   @Serial
   private static final long serialVersionUID = 5118897280592222265L;

   public InvalidCryptoParameterException() {
      super();
   }

   public InvalidCryptoParameterException(String message) {
      super(message);
   }

   public InvalidCryptoParameterException(Throwable cause) {
      super(cause);
   }

   public InvalidCryptoParameterException(String message, Throwable cause) {
      super(message, cause);
   }

}
