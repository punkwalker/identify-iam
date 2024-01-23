package analysis

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/micahhausler/aws-iam-policy/policy"
)

// var APIListRegex = regexp.MustCompile(`ecs:(Create(CapacityProvider|Cluster|Service|TaskSet)|Register(ContainerInstance|TaskDefinition)|(Run|Start)Task)`)

var ManagedPoliciesSeen []string

var APIListRegex = regexp.MustCompile(`ecs`)

func parseDocument(document *string) *policy.Policy {

	var p policy.Policy
	policyDocument, err := url.QueryUnescape(*document)

	if err != nil {
		panic(err)
	}

	err = json.Unmarshal([]byte(policyDocument), &p)

	if err != nil {
		panic(err)
	}

	return &p

}

func isAWSManaged(policyARN *string) bool {
	return strings.HasPrefix(*policyARN, "arn:aws:iam::aws:policy")
}

func isECSAction(val string) bool {
	// fmt.Printf("\n#### Checking ECSAtion in %s\n", val)
	if match := APIListRegex.FindStringSubmatch(val); match != nil {
		return true
	}
	return false

}

func hasSeenPolicy(policyARN *string) bool {
	return strings.Contains(strings.Join(ManagedPoliciesSeen, ","), *policyARN)
}

func VerifyAttachedPolicy(policyArn *string, client *iam.Client, managedPolicies *[]IAMPolicy) {

	if !hasSeenPolicy(policyArn) {

		if isAWSManaged(policyArn) {
			return
		}

		policy, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{PolicyArn: policyArn})

		attachedPolicy := IAMPolicy{
			PolicyName: *policy.Policy.PolicyName,
		}

		if err != nil {
			panic(err)
		}

		policyVersion, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{PolicyArn: policyArn, VersionId: policy.Policy.DefaultVersionId})

		if err != nil {
			panic(err)
		}

		p := parseDocument(policyVersion.PolicyVersion.Document)

		for _, statement := range p.Statements.Values() {
			actions := statement.Action.Values()
			effect := statement.Effect
			if isECSAction(strings.Join(actions, ",")) && effect == "Allow" {
				attachedPolicy.StatementIds = append(attachedPolicy.StatementIds, statement.Sid)
			}
		}

		if attachedPolicy.StatementIds != nil {
			*managedPolicies = append(*managedPolicies, attachedPolicy)
			ManagedPoliciesSeen = append(ManagedPoliciesSeen, *policyArn)
		}
	}
}

var mu sync.Mutex
var wg sync.WaitGroup

// Parallel runs a set of workers across a set of tools
func Parallel(role *string, client *iam.Client, identified *IdentifiedEntities, fn func(role *string, client *iam.Client, identified *IdentifiedEntities)) error {

	wg.Add(1)
	go func() {
		defer wg.Done()
		fn(role, client, identified)
	}()
	wg.Wait()
	return nil
}
