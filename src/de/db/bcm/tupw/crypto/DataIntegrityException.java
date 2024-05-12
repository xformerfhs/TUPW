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
 *     2018-05-25: V1.0.0: Created. fhs
 *     2019-08-02: V1.0.1: Added missing call to super in constructor without arguments. fhs
 *     2021-09-01: V1.0.2: Added serialVersionUID. fhs
 */
package de.db.bcm.tupw.crypto;

/**
 * Exception to indicate that data was tampered with
 *
 * @author FrankSchwab
 * @version 1.0.2
 */
public class DataIntegrityException extends Exception {
   //******************************************************************
   // Serialization constant
   //******************************************************************

   private static final long serialVersionUID = -1531713327290769502L;

   //******************************************************************
   // Public methods
   //******************************************************************
   public DataIntegrityException() {
      super();
   }

   public DataIntegrityException(String message) {
      super(message);
   }

   public DataIntegrityException(Throwable cause) {
      super(cause);
   }

   public DataIntegrityException(String message, Throwable cause) {
      super(message, cause);
   }

}
