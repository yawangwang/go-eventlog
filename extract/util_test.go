// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package extract

import (
	"crypto"
	"testing"
)

func TestNullTerminatedDataDigest(t *testing.T) {
	rawdata := []byte("123456")
	rawdataNullTerminated := []byte("123456\x00")
	rawdataModifyLastByte := []byte("123456\xff")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(rawdata)
	rawDigest := hasher.Sum(nil)
	hasher.Reset()
	hasher.Write(rawdataNullTerminated)
	nullTerminatedDigest := hasher.Sum(nil)
	hasher.Reset()

	if err := verifyDataDigest(hasher, rawdata, rawDigest); err != nil {
		t.Error(err)
	}
	if err := verifyDataDigest(hasher, rawdata, nullTerminatedDigest); err == nil {
		t.Errorf("non null-terminated data should not match the null-terminated digest")
	}

	// "rawdata + '\x00'" can be verified with digest("rawdata") as well as digest("rawdata + '\x00'")
	if err := verifyNullTerminatedDataDigest(hasher, rawdataNullTerminated, nullTerminatedDigest); err != nil {
		t.Error(err)
	}
	if err := verifyNullTerminatedDataDigest(hasher, rawdataNullTerminated, rawDigest); err != nil {
		t.Error(err)
	}

	if err := verifyNullTerminatedDataDigest(hasher, rawdata, nullTerminatedDigest); err == nil {
		t.Errorf("non null-terminated data should always fail")
	}
	if err := verifyNullTerminatedDataDigest(hasher, rawdataModifyLastByte, nullTerminatedDigest); err == nil {
		t.Errorf("manipulated null terminated data should fail")
	}
	if err := verifyNullTerminatedDataDigest(hasher, []byte{}, []byte{}); err == nil {
		t.Errorf("len() == 0 should always fail")
	}
}
