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

ENCRYPT_CFG="../cfg/encrypt_tunnel_crypt_off_256_empty.cfg"
DECRYPT_CFG="../cfg/decrypt.cfg"
CLEARTEXT_PCAP="../pcap/v6_cleartext_empty.pcap"
CLEARTEXT_PCAP_TXT="../pcap/v6_cleartext_empty_pcap.txt"
ENCRYPT_PCAP="../pcap/v6_encrypt_tunnel_crypt_off_256_empty.pcap"
DECRYPT_PCAP="../pcap/v6_decrypt_tunnel_crypt_off_256_empty.pcap"
DECRYPT_PCAP_TXT="../pcap/v6_decrypt_tunnel_crypt_off_256_empty_pcap.txt"
DIFF="./v6_tunnel_crypt_off_256_empty.diff"

echo "STARTING: $0"

rm -f $ENCRYPT_PCAP $DECRYPT_PCAP $DECRYPT_PCAP_TXT $DIFF

../src/psp_encrypt -c $ENCRYPT_CFG -i $CLEARTEXT_PCAP -o $ENCRYPT_PCAP
if [ $? -ne 0 ]
then
	echo "FAILED: $0"
	exit 1
fi

../src/psp_decrypt -c $DECRYPT_CFG -i $ENCRYPT_PCAP -o $DECRYPT_PCAP
if [ $? -ne 0 ]
then
	echo "FAILED: $0"
	exit 1
fi

tcpdump -qnts 0 -xx -r $DECRYPT_PCAP > $DECRYPT_PCAP_TXT
if [ $? -ne 0 ]
then
	echo "FAILED: $0"
	exit 1
fi

diff $CLEARTEXT_PCAP_TXT $DECRYPT_PCAP_TXT > $DIFF
if [ $? -ne 0 ]
then
	echo "FAILED: $0"
	exit 1
fi

if [ -s $DIFF ]
then
	echo "FAILED: $0"
	exit 1
else
	rm -f $DIFF
	echo "PASSED: $0"
fi
