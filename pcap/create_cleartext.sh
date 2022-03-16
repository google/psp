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

../src/create_pcap -f ../pcap/v4_cleartext.pcap
tcpdump -qnts 0 -xx -r ./v4_cleartext.pcap > ./v4_cleartext_pcap.txt

../src/create_pcap -f ../pcap/v4_cleartext_empty.pcap -e
tcpdump -qnts 0 -xx -r ./v4_cleartext_empty.pcap > ./v4_cleartext_empty_pcap.txt

../src/create_pcap -f ../pcap/v6_cleartext.pcap -i 6
tcpdump -qnts 0 -xx -r ./v6_cleartext.pcap > ./v6_cleartext_pcap.txt

../src/create_pcap -f ../pcap/v6_cleartext_empty.pcap -i 6 -e
tcpdump -qnts 0 -xx -r ./v6_cleartext_empty.pcap > ./v6_cleartext_empty_pcap.txt
