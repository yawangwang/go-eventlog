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
	"bytes"
	"crypto"
	"errors"
	"fmt"

	pb "github.com/google/go-eventlog/proto/state"
	"github.com/google/go-eventlog/tcg"
)

// GrubStateFromRTMRLog extracts GRUB commands from RTMR2.
func GrubStateFromRTMRLog(hash crypto.Hash, events []tcg.Event) (*pb.GrubState, error) {
	var commands []string
	for eventNum, event := range events {
		ccMRIndex := event.MRIndex()
		if ccMRIndex != 3 {
			continue
		}

		// Skip parsing EV_EVENT_TAG event since it likely comes from Linux.
		if event.UntrustedType() == tcg.EventTag {
			continue
		}

		if event.UntrustedType() != tcg.Ipl {
			return nil, fmt.Errorf("invalid event type %v for PCR%d, expected EV_IPL", event.UntrustedType().String(), ccMRIndex)
		}

		hasher := hash.New()
		suffixAt := -1
		rawData := event.RawData()
		for _, prefix := range validPrefixes {
			if bytes.HasPrefix(rawData, prefix) {
				suffixAt = len(prefix)
				break
			}
		}
		if suffixAt == -1 {
			continue
		}

		// Check the slice is not empty after the suffix, which ensures rawData[len(rawData)-1] is not part
		// of the suffix.
		if len(rawData[suffixAt:]) > 0 && rawData[len(rawData)-1] == '\x00' {
			if err := verifyNullTerminatedDataDigest(hasher, rawData[suffixAt:], event.ReplayedDigest()); err != nil {
				return nil, fmt.Errorf("invalid GRUB event (null-terminated) #%d: %v", eventNum, err)
			}
		} else {
			if err := verifyDataDigest(hasher, rawData[suffixAt:], event.ReplayedDigest()); err != nil {
				return nil, fmt.Errorf("invalid GRUB event #%d: %v", eventNum, err)
			}
		}
		hasher.Reset()
		commands = append(commands, string(rawData))
	}
	if len(commands) == 0 {
		return nil, errors.New("no GRUB measurements found")
	}
	return &pb.GrubState{Commands: commands}, nil
}
