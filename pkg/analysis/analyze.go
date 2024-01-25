package analysis

import (
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

var AnalysisList []Analysis

type Analysis interface {
	Identify(client *iam.Client, identified *IdentifiedEntities)
}

type IdentifiedEntities struct {
	Users           []IAMUser
	Roles           []IAMRole
	Groups          []IAMGroup
	ManagedPolicies []IAMPolicy
}

type IdentifiedEntity struct {
	Name     string
	Type     string
	Policies []IAMPolicy
}

type IAMUser struct {
	Name           string
	InlinePolicies []IAMPolicy
}

type IAMRole struct {
	Name           string
	InlinePolicies []IAMPolicy
}

type IAMGroup struct {
	Name           string
	InlinePolicies []IAMPolicy
}

type IAMPolicy struct {
	PolicyName   string
	StatementIds []string
}

type Configuration struct {
	IAMClient  *iam.Client
	Identified *IdentifiedEntities
}

func RegisterAnalysis(a Analysis) {
	AnalysisList = append(AnalysisList, a)
}
