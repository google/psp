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

CC = gcc
CFLAGS = -Wall

LIBS = -lpcap -lssl -lcrypto

all: create_pcap psp_encrypt psp_decrypt

create_pcap: create_pcap.c psp.h
	$(CC) $(CFLAGS) create_pcap.c -o create_pcap -lpcap

psp_encrypt: psp_encrypt.c psp.h
	$(CC) $(CFLAGS) psp_encrypt.c -o psp_encrypt $(LIBS)

psp_decrypt: psp_decrypt.c psp.h
	$(CC) $(CFLAGS) psp_decrypt.c -o psp_decrypt $(LIBS)

clean:
	rm -f create_pcap psp_encrypt psp_decrypt
