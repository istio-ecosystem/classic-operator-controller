// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package serviceentry

import (
	"net/netip"

	"istio.io/api/networking/v1alpha3"
	networkingv1alpha3 "istio.io/client-go/pkg/apis/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/config/constants"
)

const (
	IPAutoallocateStatusType = "ip-autoallocate"
)

func GetV2AddressesFromServiceEntry(se *networkingv1alpha3.ServiceEntry) []netip.Addr {
	if se == nil {
		return []netip.Addr{}
	}
	results := []netip.Addr{}
	for _, addr := range se.Status.GetAddresses() {
		parsed, err := netip.ParseAddr(addr.GetValue())
		if err != nil {
			// strange, we should have written these so it probaby should parse but for now unreadable is unusable and we move on
			continue
		}
		results = append(results, parsed)
	}
	return results
}

func ShouldV2AutoAllocateIP(se *networkingv1alpha3.ServiceEntry) bool {
	// if the feature is off we should not assign/use addresses
	if !features.EnableIPAutoallocate {
		return false
	}

	if se == nil {
		return false
	}

	// if resolution is none we cannot honor the assigned IP in the dataplane and should not assign
	if se.Spec.Resolution == v1alpha3.ServiceEntry_NONE {
		return false
	}

	// check for opt-in by user
	enabledValue, enabledFound := se.Labels[constants.EnableV2AutoAllocationLabel]
	if !enabledFound || enabledValue == "false" {
		return false
	}

	// if the user assigned their own we don't alloate or use autoassigned addresses
	if len(se.Spec.Addresses) > 0 {
		return false
	}

	return true
}
