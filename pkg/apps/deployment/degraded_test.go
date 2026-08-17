package deployment

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
)

// podListerFixture is a minimal PodLister for degraded-condition unit tests.
type podListerFixture struct {
	pods []*corev1.Pod
	err  error
}

func (f *podListerFixture) List(_ labels.Selector) ([]*corev1.Pod, error) {
	return f.pods, f.err
}

func (f *podListerFixture) Pods(_ string) corev1listers.PodNamespaceLister {
	return &podNamespaceListerFixture{f}
}

type podNamespaceListerFixture struct{ *podListerFixture }

func (f *podNamespaceListerFixture) List(_ labels.Selector) ([]*corev1.Pod, error) {
	return f.pods, f.err
}

func (f *podNamespaceListerFixture) Get(_ string) (*corev1.Pod, error) {
	panic("not implemented")
}

// deploy builds a minimal Deployment for testing.
func deploy(opts ...func(*appsv1.Deployment)) *appsv1.Deployment {
	d := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "ns"},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](3),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}},
			},
		},
		Status: appsv1.DeploymentStatus{
			AvailableReplicas: 3,
			UpdatedReplicas:   3,
			Conditions: []appsv1.DeploymentCondition{
				{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable"},
			},
		},
	}
	for _, o := range opts {
		o(d)
	}
	return d
}

func withPDE(msg string) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) {
		d.Status.Conditions = []appsv1.DeploymentCondition{
			{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionFalse, Reason: "ProgressDeadlineExceeded", Message: msg},
		}
	}
}

func withAvailable(n int32) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) { d.Status.AvailableReplicas = n }
}

func withReplicas(n int32) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) { d.Spec.Replicas = ptr.To(n) }
}

func withMinReady(s int32) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) { d.Spec.MinReadySeconds = s }
}

func withProgressDeadline(s int32) func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) { d.Spec.ProgressDeadlineSeconds = ptr.To(s) }
}

func withActiveRollout() func(*appsv1.Deployment) {
	return func(d *appsv1.Deployment) {
		d.Status.Conditions = []appsv1.DeploymentCondition{
			{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "ReplicaSetUpdated"},
		}
	}
}

func newPod(name string, ready bool, created time.Duration, opts ...func(*corev1.Pod)) *corev1.Pod {
	now := time.Now()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "ns",
			CreationTimestamp: metav1.NewTime(now.Add(-created)),
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: conditionStatus(ready), LastTransitionTime: metav1.NewTime(now.Add(-created))},
			},
		},
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

func conditionStatus(ready bool) corev1.ConditionStatus {
	if ready {
		return corev1.ConditionTrue
	}
	return corev1.ConditionFalse
}

func withReadyTransition(ago time.Duration) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		for i := range p.Status.Conditions {
			if p.Status.Conditions[i].Type == corev1.PodReady {
				p.Status.Conditions[i].LastTransitionTime = metav1.NewTime(time.Now().Add(-ago))
			}
		}
	}
}

func withDeletionTimestamp() func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		t := metav1.Now()
		p.DeletionTimestamp = &t
	}
}

func TestDeploymentDegradedCondition(t *testing.T) {
	now := time.Now()
	listerEmpty := &podListerFixture{}
	listerErr := &podListerFixture{err: fmt.Errorf("list failed")}

	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		lister     *podListerFixture
		wantCond   operatorv1.OperatorCondition
		wantErr    bool
	}{
		{
			name:       "progress deadline exceeded",
			deployment: deploy(withPDE("took too long")),
			lister:     listerEmpty,
			wantCond: operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeDegraded,
				Status:  operatorv1.ConditionTrue,
				Reason:  "ProgressDeadlineExceeded",
				Message: "deployment/web.ns has timed out progressing: took too long",
			},
		},
		{
			name:       "all replicas available after successful rollout",
			deployment: deploy(),
			lister:     listerEmpty,
			wantCond: operatorv1.OperatorCondition{
				Type:   operatorv1.OperatorStatusTypeDegraded,
				Status: operatorv1.ConditionFalse,
				Reason: "AsExpected",
			},
		},
		{
			name:       "active rollout not degraded even when unavailable",
			deployment: deploy(withActiveRollout(), withAvailable(1)),
			lister:     listerEmpty,
			wantCond: operatorv1.OperatorCondition{
				Type:   operatorv1.OperatorStatusTypeDegraded,
				Status: operatorv1.ConditionFalse,
				Reason: "AsExpected",
			},
		},
		{
			name:       "progressed but pods starting — within deadline — not degraded",
			deployment: deploy(withAvailable(1)),
			lister: &podListerFixture{pods: []*corev1.Pod{
				newPod("web-1", false, 1*time.Minute), // 1m old, deadline 10m
			}},
			wantCond: operatorv1.OperatorCondition{
				Type:   operatorv1.OperatorStatusTypeDegraded,
				Status: operatorv1.ConditionFalse,
				Reason: "AsExpected",
			},
		},
		{
			name:       "progressed but pod failing past deadline",
			deployment: deploy(withAvailable(2)),
			lister: &podListerFixture{pods: []*corev1.Pod{func() *corev1.Pod {
				p := newPod("web-crash", false, 20*time.Minute)
				p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", Ready: false, RestartCount: 5}}
				return p
			}()}},
			wantCond: operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeDegraded,
				Status:  operatorv1.ConditionTrue,
				Reason:  "UnavailablePod",
				Message: "1 of 3 requested instances are unavailable for web.ns (container is crashlooping in web-crash pod)",
			},
		},
		{
			name:       "zero available — no pods — degraded",
			deployment: deploy(withAvailable(0)),
			lister:     &podListerFixture{pods: []*corev1.Pod{}},
			wantCond: operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeDegraded,
				Status:  operatorv1.ConditionTrue,
				Reason:  "UnavailablePod",
				Message: `3 of 3 requested instances are unavailable for web.ns (no pods found with labels "app=web")`,
			},
		},
		{
			name:       "pod list error propagated",
			deployment: deploy(withAvailable(2)),
			lister:     listerErr,
			wantCond: operatorv1.OperatorCondition{
				Type:   operatorv1.OperatorStatusTypeDegraded,
				Status: operatorv1.ConditionFalse,
				Reason: "AsExpected",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeploymentDegradedCondition(tt.deployment, tt.lister, now)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if d := cmp.Diff(tt.wantCond, got); d != "" {
				t.Errorf("condition mismatch (-want +got):\n%s", d)
			}
		})
	}
}

func TestHasFailingPods(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		deployment *appsv1.Deployment
		pods       []*corev1.Pod
		podErr     error
		wantFail   bool
		wantErr    bool
	}{
		{
			name:       "no pods — not failing",
			deployment: deploy(),
			pods:       []*corev1.Pod{},
			wantFail:   false,
		},
		{
			name:       "ready pod within deadline — not failing",
			deployment: deploy(),
			pods:       []*corev1.Pod{newPod("p", true, 2*time.Minute)},
			wantFail:   false,
		},
		{
			name:       "not-ready pod within deadline — not failing",
			deployment: deploy(),
			pods:       []*corev1.Pod{newPod("p", false, 2*time.Minute)},
			wantFail:   false,
		},
		{
			name:       "not-ready pod past deadline — failing",
			deployment: deploy(),
			pods:       []*corev1.Pod{newPod("p", false, 20*time.Minute)},
			wantFail:   true,
		},
		{
			name:       "terminating pod past deadline — not failing",
			deployment: deploy(),
			pods:       []*corev1.Pod{newPod("p", false, 20*time.Minute, withDeletionTimestamp())},
			wantFail:   false,
		},
		{
			name:       "pod list error",
			deployment: deploy(),
			podErr:     fmt.Errorf("kube error"),
			wantFail:   false,
			wantErr:    true,
		},
		{
			// MinReadySeconds=60, deadline=600s. Combined=660s (11m).
			// Pod created 15m ago → past combined deadline → check is relevant.
			// Ready transition 10s ago < MinReady (60s) → flapping → failing.
			name:       "flapping ready past combined deadline — failing",
			deployment: deploy(withMinReady(60)),
			pods: []*corev1.Pod{
				newPod("p", true, 15*time.Minute, withReadyTransition(10*time.Second)),
			},
			wantFail: true,
		},
		{
			// Combined deadline not yet elapsed → flapping check not relevant → not failing.
			name:       "flapping ready within combined deadline — not failing",
			deployment: deploy(withMinReady(300)),
			pods: []*corev1.Pod{
				// Created 8m ago; combined deadline = 600+300 = 900s (15m). 8m < 15m → not relevant.
				newPod("p", true, 8*time.Minute, withReadyTransition(10*time.Second)),
			},
			wantFail: false,
		},
		{
			// Past combined deadline but Ready transition is older than MinReadySeconds → stable → not failing.
			name:       "stable ready past combined deadline — not failing",
			deployment: deploy(withMinReady(60)),
			pods: []*corev1.Pod{
				// Created 15m ago; combined deadline=660s (11m) → relevant. Ready 5m ago > 60s → stable.
				newPod("p", true, 15*time.Minute, withReadyTransition(5*time.Minute)),
			},
			wantFail: false,
		},
		{
			// MinReadySeconds=0: flapping detection disabled entirely.
			name:       "minReady=0 no flapping detection",
			deployment: deploy(withMinReady(0)),
			pods: []*corev1.Pod{
				// Ready but transitioned just now: with MinReady=0, check is disabled.
				newPod("p", true, 20*time.Minute, withReadyTransition(1*time.Second)),
			},
			wantFail: false,
		},
		{
			name:       "custom progress deadline — pod within custom deadline not failing",
			deployment: deploy(withProgressDeadline(30)),
			pods:       []*corev1.Pod{newPod("p", false, 20*time.Second)},
			wantFail:   false,
		},
		{
			name:       "custom progress deadline — pod past custom deadline failing",
			deployment: deploy(withProgressDeadline(30)),
			pods:       []*corev1.Pod{newPod("p", false, 2*time.Minute)},
			wantFail:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := &podListerFixture{pods: tt.pods, err: tt.podErr}
			got, err := HasFailingPods(tt.deployment, lister, now)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.wantFail {
				t.Errorf("HasFailingPods = %v, want %v", got, tt.wantFail)
			}
		})
	}
}
