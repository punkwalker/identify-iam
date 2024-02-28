package analysis

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

type Configuration struct {
	Queue               chan Entity
	PageSize            int32
	PolicyDecisionCache map[string]string
	IAMClient           *iam.Client
	Identified          *IdentifiedEntities
}

func (c Configuration) NewConfig() (*Configuration, error) {

	newQueue := make(chan Entity)
	newPolicyDecisionCache := map[string]string{}

	awsConfig, err := config.LoadDefaultConfig(context.TODO())

	client := iam.NewFromConfig(awsConfig)

	defaultConfig := Configuration{
		Queue:               newQueue,
		PageSize:            200,
		PolicyDecisionCache: newPolicyDecisionCache,
		IAMClient:           client,
		Identified:          &IdentifiedEntities{},
	}

	return &defaultConfig, err
}

func (c Configuration) NewWaitGroup() *sync.WaitGroup {
	return &sync.WaitGroup{}
}

func (c Configuration) NewMutex() *sync.Mutex {
	return &sync.Mutex{}
}
