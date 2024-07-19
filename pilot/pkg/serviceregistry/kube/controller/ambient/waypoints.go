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

// nolint: gocritic
package ambient

import (
	"net/netip"
	"strconv"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/apis/v1beta1"

	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schema/gvk"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/ptr"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/workloadapi"
)

type InboundBinding struct {
	Port     uint32
	Protocol workloadapi.ApplicationTunnel_Protocol
}

type Waypoint struct {
	krt.Named

	// Addresses this Waypoint is reachable by. For stock Istio waypoints, this
	// is is usually the VIP. Tere will always be at least one address in this
	// list.
	Addresses []netip.Addr

	// DefaultBinding for an inbound zTunnel to use to connect to a Waypoint it captures.
	// This is applied to the Workloads that are instances of the current Waypoint.
	DefaultBinding InboundBinding

	// TrafficType controls whether Service or Workload can reference this
	// waypoint. Must be one of "all", "service", "workload".
	TrafficType string

	// ServiceAccounts from instances of the waypoint.
	// This only handles Pods. If we wish to support non-pod waypoints, we'll
	// want to index ServiceEntry/WorkloadEntry or possibly allow specifying
	// the ServiceAccounts directly on a Gateway resource.
	ServiceAccounts []string
	AllowedRoutes   WaypointSelector
}

// fetchWaypointForInstance attempts to find a Waypoint a given object is an instance of.
// TODO should this also lookup waypoints by workload.addresses + workload.services[].vip?
// ServiceEntry and WorkloadEntry likely won't have the gateway-name label.
func fetchWaypointForInstance(ctx krt.HandlerContext, Waypoints krt.Collection[Waypoint], o metav1.ObjectMeta) *Waypoint {
	name, namespace := o.GetLabels()[constants.GatewayNameLabel], o.Namespace
	if name == "" {
		return nil
	}
	return krt.FetchOne[Waypoint](ctx, Waypoints, krt.FilterKey(namespace+"/"+name))
}

// fetchWaypointForTarget attempts to find the waypoint that should handle traffic for a given service or workload
func fetchWaypointForTarget(
	ctx krt.HandlerContext,
	waypoints krt.Collection[Waypoint],
	namespaces krt.Collection[*v1.Namespace],
	o metav1.ObjectMeta,
) *Waypoint {
	// namespace to be used when the annotation doesn't include a namespace
	fallbackNamespace := o.Namespace
	// try fetching the waypoint defined on the object itself
	wp, isNone := getUseWaypoint(o, fallbackNamespace)
	if isNone {
		// we've got a local override here opting out of waypoint
		return nil
	}
	if wp != nil {
		// plausible the object has a waypoint defined but that waypoint's underlying gateway is not ready, in this case we'd return nil here even if
		// the namespace-defined waypoint is ready and would not be nil... is this OK or should we handle that? Could lead to odd behavior when
		// o was reliant on the namespace waypoint and then get's a use-waypoint label added before that gateway is ready.
		// goes from having a waypoint to having no waypoint and then eventually gets a waypoint back
		w := krt.FetchOne[Waypoint](ctx, waypoints, krt.FilterKey(wp.ResourceName()))
		if w != nil {
			if !w.AllowsAttachmentFromNamespaceOrLookup(ctx, namespaces, fallbackNamespace) {
				return nil
			}
			return w
		}
		return nil
	}

	// try fetching the namespace-defined waypoint
	namespace := ptr.OrEmpty[*v1.Namespace](krt.FetchOne[*v1.Namespace](ctx, namespaces, krt.FilterKey(o.Namespace)))
	// this probably should never be nil. How would o exist in a namespace we know nothing about? maybe edge case of starting the controller or ns delete?
	if namespace != nil {
		// toss isNone, we don't need to know /why/ we got nil
		wp, _ := getUseWaypoint(namespace.ObjectMeta, fallbackNamespace)
		if wp != nil {
			w := krt.FetchOne[Waypoint](ctx, waypoints, krt.FilterKey(wp.ResourceName()))
			if w != nil {
				if !w.AllowsAttachmentFromNamespace(namespace) {
					return nil
				}
				return w
			}
			return nil
		}
	}

	// neither o nor it's namespace has a use-waypoint label
	return nil
}

func fetchWaypointForService(ctx krt.HandlerContext, Waypoints krt.Collection[Waypoint],
	Namespaces krt.Collection[*v1.Namespace], o metav1.ObjectMeta,
) *Waypoint {
	w := fetchWaypointForTarget(ctx, Waypoints, Namespaces, o)
	if w != nil {
		if w.TrafficType == constants.ServiceTraffic || w.TrafficType == constants.AllTraffic {
			return w
		}
		// Waypoint does not support Service traffic
		log.Debugf("Unable to add waypoint %s/%s; traffic type %s not supported for %s/%s",
			w.Namespace, w.Name, w.TrafficType, o.Namespace, o.Name)
	}
	return nil
}

func fetchWaypointForWorkload(ctx krt.HandlerContext, Waypoints krt.Collection[Waypoint],
	Namespaces krt.Collection[*v1.Namespace], o metav1.ObjectMeta,
) *Waypoint {
	w := fetchWaypointForTarget(ctx, Waypoints, Namespaces, o)
	if w != nil {
		if w.TrafficType == constants.WorkloadTraffic || w.TrafficType == constants.AllTraffic {
			return w
		}
		// Waypoint does not support Workload traffic
		log.Debugf("Unable to add waypoint %s/%s; traffic type %s not supported for %s/%s",
			w.Namespace, w.Name, w.TrafficType, o.Namespace, o.Name)
	}
	return nil
}

// getUseWaypoint takes objectMeta and a defaultNamespace
// it looks for the istio.io/use-waypoint label and parses it
// if there is no namespace provided in the label the default namespace will be used
// defaultNamespace avoids the need to infer when object meta from a namespace was given
func getUseWaypoint(meta metav1.ObjectMeta, defaultNamespace string) (named *krt.Named, isNone bool) {
	if labelValue, ok := meta.Labels[constants.AmbientUseWaypointLabel]; ok {
		// NOTE: this means Istio reserves the word "none" in this field with a special meaning
		//   a waypoint named "none" cannot be used and will be ignored
		if labelValue == "none" {
			return nil, true
		}
		namespace := defaultNamespace
		if override, f := meta.Labels[constants.AmbientUseWaypointNamespaceLabel]; f {
			namespace = override
		}
		return &krt.Named{
			Name:      labelValue,
			Namespace: namespace,
		}, false
	}
	return nil, false
}

func (w Waypoint) ResourceName() string {
	return w.GetNamespace() + "/" + w.GetName()
}

func WaypointsCollection(
	gateways krt.Collection[*v1beta1.Gateway],
	gatewayClasses krt.Collection[*v1beta1.GatewayClass],
	pods krt.Collection[*v1.Pod],
) krt.Collection[Waypoint] {
	podsByNamespace := krt.NewNamespaceIndex(pods)
	return krt.NewCollection(gateways, func(ctx krt.HandlerContext, gateway *v1beta1.Gateway) *Waypoint {
		if len(gateway.Status.Addresses) == 0 {
			// gateway.Status.Addresses should only be populated once the Waypoint's deployment has at least 1 ready pod, it should never be removed after going ready
			// ignore Kubernetes Gateways which aren't waypoints
			return nil
		}

		instances := krt.Fetch(ctx, pods, krt.FilterLabel(map[string]string{
			constants.GatewayNameLabel: gateway.Name,
		}), krt.FilterIndex(podsByNamespace, gateway.Namespace))

		serviceAccounts := slices.Map(instances, func(p *v1.Pod) string {
			return p.Spec.ServiceAccountName
		})

		// default traffic type if neither GatewayClass nor Gateway specify a type
		trafficType := constants.ServiceTraffic

		gatewayClass := ptr.OrEmpty(krt.FetchOne(ctx, gatewayClasses, krt.FilterKey(string(gateway.Spec.GatewayClassName))))
		if gatewayClass == nil {
			log.Warnf("could not find GatewayClass %s for Gateway %s/%s", gateway.Spec.GatewayClassName, gateway.Namespace, gateway.Name)
		} else if tt, found := gatewayClass.Labels[constants.AmbientWaypointForTrafficTypeLabel]; found {
			// Check for a declared traffic type that is allowed to pass through the Waypoint's GatewayClass
			trafficType = tt
		}

		// Check for a declared traffic type that is allowed to pass through the Waypoint
		if tt, found := gateway.Labels[constants.AmbientWaypointForTrafficTypeLabel]; found {
			trafficType = tt
		}

		return makeWaypoint(gateway, gatewayClass, serviceAccounts, trafficType)
	}, krt.WithName("Waypoints"))
}

func makeInboundBinding(gateway *v1beta1.Gateway, gatewayClass *v1beta1.GatewayClass) InboundBinding {
	annotation, ok := getGatewayOrGatewayClassAnnotation(gateway, gatewayClass)
	if !ok {
		return InboundBinding{}
	}

	// format is either `protocol` or `protocol/port`
	parts := strings.Split(annotation, "/")
	if len(parts) == 0 || len(parts) > 2 {
		log.Warnf("invalid value %q for %s. Must be of the format \"<protocol>\" or \"<protocol>/<port>\".", annotation, constants.AmbientWaypointInboundBinding)
		return InboundBinding{}
	}

	// parse protocol
	var protocol workloadapi.ApplicationTunnel_Protocol
	switch parts[0] {
	case "NONE":
		protocol = workloadapi.ApplicationTunnel_NONE
	case "PROXY":
		protocol = workloadapi.ApplicationTunnel_PROXY
	default:
		// Only PROXY is supported for now.
		log.Warnf("invalid protocol %s for %s. Only NONE or PROXY are supported.", parts[0], constants.AmbientWaypointInboundBinding)
		return InboundBinding{}
	}

	// parse port
	port := uint32(0)
	if len(parts) == 2 {
		parsed, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			log.Warnf("invalid port %s for %s.", parts[1], constants.AmbientWaypointInboundBinding)
		}
		port = uint32(parsed)
	}

	return InboundBinding{
		Port:     port,
		Protocol: protocol,
	}
}

func getGatewayOrGatewayClassAnnotation(gateway *v1beta1.Gateway, class *v1beta1.GatewayClass) (string, bool) {
	// Gateway > GatewayClass
	annotation, ok := gateway.Annotations[constants.AmbientWaypointInboundBinding]
	if ok {
		return annotation, true
	}
	if class != nil {
		annotation, ok := class.Annotations[constants.AmbientWaypointInboundBinding]
		if ok {
			return annotation, true
		}
	}
	return "", false
}

func makeWaypoint(
	gateway *v1beta1.Gateway,
	gatewayClass *v1beta1.GatewayClass,
	serviceAccounts []string,
	trafficType string,
) *Waypoint {
	return &Waypoint{
		Named:           krt.NewNamed(gateway),
		Addresses:       getGatewayAddrs(gateway),
		DefaultBinding:  makeInboundBinding(gateway, gatewayClass),
		AllowedRoutes:   makeAllowedRoutes(gateway),
		TrafficType:     trafficType,
		ServiceAccounts: slices.Sort(serviceAccounts),
	}
}

type WaypointSelector struct {
	FromNamespaces v1beta1.FromNamespaces
	Selector       labels.Selector
}

func (w Waypoint) AllowsAttachmentFromNamespaceOrLookup(ctx krt.HandlerContext, Namespaces krt.Collection[*v1.Namespace], namespace string) bool {
	switch w.AllowedRoutes.FromNamespaces {
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSelector:
		ns := ptr.OrEmpty[*v1.Namespace](krt.FetchOne[*v1.Namespace](ctx, Namespaces, krt.FilterKey(namespace)))
		return w.AllowedRoutes.Selector.Matches(labels.Set(ns.GetLabels()))
	case gatewayv1.NamespacesFromSame:
		return w.Namespace == namespace
	default:
		// Should be impossible
		return w.Namespace == namespace
	}
}

func (w Waypoint) AllowsAttachmentFromNamespace(namespace *v1.Namespace) bool {
	switch w.AllowedRoutes.FromNamespaces {
	case gatewayv1.NamespacesFromAll:
		return true
	case gatewayv1.NamespacesFromSelector:
		return w.AllowedRoutes.Selector.Matches(labels.Set(namespace.GetLabels()))
	case gatewayv1.NamespacesFromSame:
		return w.Namespace == namespace.Name
	default:
		// Should be impossible
		return w.Namespace == namespace.Name
	}
}

func makeAllowedRoutes(gateway *v1beta1.Gateway) WaypointSelector {
	for _, l := range gateway.Spec.Listeners {
		if l.Protocol == "HBONE" && l.Port == 15008 {
			// This is our HBONE listener
			if l.AllowedRoutes == nil || l.AllowedRoutes.Namespaces == nil {
				break
			}
			al := *l.AllowedRoutes.Namespaces
			from := ptr.OrDefault(al.From, gatewayv1.NamespacesFromSame)
			label, _ := metav1.LabelSelectorAsSelector(l.AllowedRoutes.Namespaces.Selector)
			return WaypointSelector{
				FromNamespaces: from,
				Selector:       label,
			}
		}
	}
	return WaypointSelector{
		FromNamespaces: gatewayv1.NamespacesFromSame,
	}
}

func getGatewayAddrs(gw *v1beta1.Gateway) []netip.Addr {
	// Currently, we only look at one address. Probably this should be made more robust
	ip, err := netip.ParseAddr(gw.Status.Addresses[0].Value)
	if err == nil {
		return []netip.Addr{ip}
	}
	log.Errorf("Unable to parse IP address in status of %v/%v/%v", gvk.KubernetesGateway, gw.Namespace, gw.Name)
	return nil
}
