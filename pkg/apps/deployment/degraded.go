package deployment

import (
	"errors"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/utils/ptr"

	operatorv1 "github.com/openshift/api/operator/v1"
)

// DeploymentDegradedCondition computes an operator Degraded condition from the
// deployment status and pod state.
func DeploymentDegradedCondition(deployment *appsv1.Deployment, podsLister corev1listers.PodLister, now time.Time) (operatorv1.OperatorCondition, error) {
	timedOutMessage, timedOut := HasDeploymentTimedOutProgressing(deployment.Status)
	if timedOut {
		return operatorv1.OperatorCondition{
			Type:    operatorv1.OperatorStatusTypeDegraded,
			Status:  operatorv1.ConditionTrue,
			Reason:  "ProgressDeadlineExceeded",
			Message: fmt.Sprintf("deployment/%s.%s has timed out progressing: %s", deployment.Name, deployment.Namespace, timedOutMessage),
		}, nil
	}

	desiredReplicas := ptr.Deref(deployment.Spec.Replicas, 1)
	if HasDeploymentProgressed(deployment.Status) && deployment.Status.AvailableReplicas < desiredReplicas {
		hasFailing, failingErr := HasFailingPods(deployment, podsLister, now)
		if hasFailing || deployment.Status.AvailableReplicas == 0 {
			containerMessages, containerErr := PodContainersStatus(deployment, podsLister)
			var failureDescription string
			if len(containerMessages) > 0 {
				failureDescription = " (" + strings.Join(containerMessages, ", ") + ")"
			}
			numUnavailable := desiredReplicas - deployment.Status.AvailableReplicas
			return operatorv1.OperatorCondition{
				Type:    operatorv1.OperatorStatusTypeDegraded,
				Status:  operatorv1.ConditionTrue,
				Reason:  "UnavailablePod",
				Message: fmt.Sprintf("%d of %d requested instances are unavailable for %s.%s%s", numUnavailable, desiredReplicas, deployment.Name, deployment.Namespace, failureDescription),
			}, errors.Join(failingErr, containerErr)
		}
		return operatorv1.OperatorCondition{
			Type:   operatorv1.OperatorStatusTypeDegraded,
			Status: operatorv1.ConditionFalse,
			Reason: "AsExpected",
		}, failingErr
	}

	return operatorv1.OperatorCondition{
		Type:   operatorv1.OperatorStatusTypeDegraded,
		Status: operatorv1.ConditionFalse,
		Reason: "AsExpected",
	}, nil
}

// HasFailingPods returns true if any non-terminating pod belonging to the
// deployment has been failing to become Ready past its ProgressDeadlineSeconds,
// or if a pod is flapping its Ready condition within MinReadySeconds after the
// combined (ProgressDeadlineSeconds + MinReadySeconds) window has elapsed.
func HasFailingPods(deployment *appsv1.Deployment, podsLister corev1listers.PodLister, now time.Time) (bool, error) {
	selector, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil {
		return false, err
	}
	pods, err := podsLister.Pods(deployment.Namespace).List(selector)
	if err != nil {
		return false, err
	}

	progressDeadline := time.Duration(ptr.Deref(deployment.Spec.ProgressDeadlineSeconds, 600)) * time.Second
	minReady := time.Duration(deployment.Spec.MinReadySeconds) * time.Second

	for _, pod := range pods {
		if pod.DeletionTimestamp != nil {
			continue
		}

		readyCond := findPodReadyCondition(pod)
		deadline := pod.CreationTimestamp.Time.Add(progressDeadline)

		if (readyCond == nil || readyCond.Status != corev1.ConditionTrue) && now.After(deadline) {
			return true, nil
		}

		// Detect flapping Ready condition: the pod is currently Ready but its
		// Ready condition transitioned too recently to count as stable
		// (hasn't stayed continuously ready for MinReadySeconds).
		//
		// Only relevant after ProgressDeadlineSeconds + MinReadySeconds.
		if minReady > 0 && readyCond != nil && readyCond.Status == corev1.ConditionTrue {
			isRelevant := now.After(pod.CreationTimestamp.Time.Add(progressDeadline + minReady))
			if isRelevant && now.Sub(readyCond.LastTransitionTime.Time) < minReady {
				return true, nil
			}
		}
	}
	return false, nil
}

func findPodReadyCondition(pod *corev1.Pod) *corev1.PodCondition {
	for i := range pod.Status.Conditions {
		if pod.Status.Conditions[i].Type == corev1.PodReady {
			return &pod.Status.Conditions[i]
		}
	}
	return nil
}
