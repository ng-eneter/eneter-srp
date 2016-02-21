/*
 * Project: Eneter.SecureRemotePassword
 * Author:  Ondrej Uzovic
 * 
 * Copyright © Ondrej Uzovic 2016
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
*/

using System;
using System.Runtime.Serialization;

namespace Eneter.SecureRemotePassword
{
    /// <summary>
    /// Data message to send the login request from client to service.
    /// </summary>
    /// <remarks>
    /// Client sends this message to initiate the authentication.
    /// </remarks>
#if !SILVERLIGHT
    [Serializable]
#endif
    [DataContract]
    public class LoginRequestMessage
    {
        /// <summary>
        /// User name
        /// </summary>
        [DataMember]
        public string UserName { get; set; }

        /// <summary>
        /// Client public ephemeral value 'A'
        /// </summary>
        [DataMember]
        public byte[] A { get; set; }
    }
}
