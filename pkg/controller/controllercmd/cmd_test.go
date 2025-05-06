package controllercmd

import (
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/version"
	"k8s.io/utils/clock"

	configv1 "github.com/openshift/api/config/v1"
)

func TestControllerCommandConfig_controllerConfig_LeaderElection(t *testing.T) {
	const configFile = "testdata/config_leader_election.yaml"
	tests := []struct {
		name              string
		initCommandConfig func(*ControllerCommandConfig)
		expectedConfig    configv1.LeaderElection
	}{
		{
			name: "config file only",
			expectedConfig: configv1.LeaderElection{
				Name:      "operator1",
				Namespace: "operator-ns",
			},
		},
		{
			name: "LeaseName set",
			initCommandConfig: func(c *ControllerCommandConfig) {
				c.LeaseName = "custom-lease-name"
			},
			expectedConfig: configv1.LeaderElection{
				Name:      "custom-lease-name",
				Namespace: "operator-ns",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewControllerCommandConfig("operator", version.Info{}, nil, clock.RealClock{})
			c.basicFlags.ConfigFile = configFile

			if test.initCommandConfig != nil {
				test.initCommandConfig(c)
			}

			_, config, _, _, err := c.controllerConfig()
			if err != nil {
				t.Fatalf("error building controller config: %v", err)
			}

			if !reflect.DeepEqual(config.LeaderElection, test.expectedConfig) {
				t.Errorf("unexpected LeaderElection config; expected=%#v, got=%#v", test.expectedConfig, config.LeaderElection)
			}
		})
	}
}
