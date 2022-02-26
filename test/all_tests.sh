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

pass=0
fail=0

run_test ()
{
	$1
	if [ $? -ne 0 ]; then
		((fail++))
	else
		((pass++))
	fi
	echo ""
}

run_test ./v4_transport_crypt_off_128.sh
run_test ./v4_transport_no_crypt_off_128.sh
run_test ./v4_transport_crypt_off_256.sh
run_test ./v4_transport_no_crypt_off_256.sh
run_test ./v4_tunnel_crypt_off_128.sh
run_test ./v4_tunnel_no_crypt_off_128.sh
run_test ./v4_tunnel_crypt_off_256.sh
run_test ./v4_tunnel_no_crypt_off_256.sh
run_test ./v6_transport_crypt_off_128.sh
run_test ./v6_transport_no_crypt_off_128.sh
run_test ./v6_transport_crypt_off_256.sh
run_test ./v6_transport_no_crypt_off_256.sh
run_test ./v6_tunnel_crypt_off_128.sh
run_test ./v6_tunnel_no_crypt_off_128.sh
run_test ./v6_tunnel_crypt_off_256.sh
run_test ./v6_tunnel_no_crypt_off_256.sh
run_test ./v4_transport_crypt_off_128_empty.sh
run_test ./v6_tunnel_crypt_off_256_empty.sh
run_test ./v4_transport_crypt_off_128_vc.sh
run_test ./v4_transport_no_crypt_off_128_vc.sh
run_test ./v6_tunnel_crypt_off_256_vc.sh
run_test ./v6_tunnel_no_crypt_off_256_vc.sh
run_test ./v4_transport_crypt_off_128_err.sh
run_test ./v6_tunnel_crypt_off_256_err.sh
echo "$pass tests PASSED, $fail tests FAILED"

