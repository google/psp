#!/bin/bash

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ENCRYPT_CFG="../cfg/encrypt_tunnel_crypt_off_256.cfg"
DECRYPT_CFG="../cfg/decrypt.cfg"
CLEARTEXT_PCAP="../pcap/v6_cleartext.pcap"
CLEARTEXT_PCAP_TXT="../pcap/v6_cleartext_pcap.txt"
ENCRYPT_PCAP="../pcap/v6_encrypt_tunnel_crypt_off_256.pcap"
DECRYPT_PCAP="../pcap/v6_decrypt_tunnel_crypt_off_256.pcap"

echo "STARTING: $0"

rm -f $ENCRYPT_PCAP $DECRYPT_PCAP $DECRYPT_PCAP_TXT $DIFF

../src/psp_encrypt -c $ENCRYPT_CFG -i $CLEARTEXT_PCAP -o $ENCRYPT_PCAP -e
if [ $? -ne 0 ]
then
	echo "FAILED: $0"
	exit 1
fi

../src/psp_decrypt -c $DECRYPT_CFG -i $ENCRYPT_PCAP -o $DECRYPT_PCAP
if [ $? -eq 0 ]
then
	echo "FAILED: $0"
	exit 1
fi

echo "PASSED: $0"
