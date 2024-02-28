package analysis

import (
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

var AnalysisList []Analysis

type Analysis interface {
	Identify(cfg *Configuration, opts *Options)
}

type IdentifiedEntities struct {
	Users  []IdentifiedEntity
	Roles  []IdentifiedEntity
	Groups []IdentifiedEntity
}

type IdentifiedEntity struct {
	Name             string
	Decision         types.PolicyEvaluationDecisionType
	DeniedByPolicies []string
}

type Entity struct {
	Name     string
	Type     string
	Policies []string
}

func RegisterAnalysis(a Analysis) {
	AnalysisList = append(AnalysisList, a)
}
