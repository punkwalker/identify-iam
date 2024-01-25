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

var APIListRegex = regexp.MustCompile(`(ecs:(Create(CapacityProvider|Cluster|Service|TaskSet)|Register(ContainerInstance|TaskDefinition)|(Run|Start)Task))|(ecs:(Create\*|Register\*|Run\*|Start*))`)

var ManagedPoliciesSeen []string

var NewAPIegex = regexp.MustCompile(`ecs:(TagResource|Tag*)`)

var mu sync.Mutex

var wg sync.WaitGroup

var BatchSize = 10

func parseDocument(policyDocument *string) *policy.Policy {

	var p policy.Policy

	err := json.Unmarshal([]byte(*policyDocument), &p)

	if err != nil {
		panic(err)
	}

	return &p

}

func isAWSManaged(policyARN *string) bool {
	return strings.HasPrefix(*policyARN, "arn:aws:iam::aws:policy")
}

func isAction(actionsRegex *regexp.Regexp, policyDocument *string) bool {
	return actionsRegex.MatchString(*policyDocument)
}

func processPolicy(policyDocument *string, policy *IAMPolicy) {

	p := parseDocument(policyDocument)

	for _, statement := range p.Statements.Values() {
		effect := statement.Effect
		actions := ""

		if effect == "Allow" && statement.Action != nil { // We are only interested in Action if the effect is Allow
			actions = strings.Join(statement.Action.Values(), ",")
		} else if effect == "Deny" && statement.NotAction != nil { // We are only interested in NotAction if the effect is Deny
			actions = strings.Join(statement.NotAction.Values(), ",")
		}

		// Proceed Only if Actions do not have ecs:*
		if !strings.Contains(actions, "ecs:*") {

			// Proceed only if ecs:TagResource is not present
			if !isAction(NewAPIegex, &actions) {

				// Proceed only if we see any of the associated API action in statement
				if isAction(APIListRegex, &actions) {
					policy.StatementIds = append(policy.StatementIds, statement.Sid)
				}

			} else {

				break // Break as we found at least one ECSTagAction
			}
		}

	}
}

func hasSeenPolicy(policyARN *string) bool {
	return strings.Contains(strings.Join(ManagedPoliciesSeen, ","), *policyARN)
}

func VerifyAttachedPolicy(policyArn *string, client *iam.Client, managedPolicies *[]IAMPolicy) {

	if !hasSeenPolicy(policyArn) {

		ManagedPoliciesSeen = append(ManagedPoliciesSeen, *policyArn)

		if isAWSManaged(policyArn) {
			return
		}

		policy, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{PolicyArn: policyArn})

		if err != nil {
			panic(err)
		}

		policyVersion, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{PolicyArn: policyArn, VersionId: policy.Policy.DefaultVersionId})

		if err != nil {
			panic(err)
		}
		policyDocument, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
		if err != nil {
			panic(err)
		}

		// Proceed Only if we see any of the associated API action
		if isAction(APIListRegex, &policyDocument) {

			attachedPolicy := IAMPolicy{
				PolicyName: *policy.Policy.PolicyName,
			}

			processPolicy(&policyDocument, &attachedPolicy)

			if attachedPolicy.StatementIds != nil {
				*managedPolicies = append(*managedPolicies, attachedPolicy)
			}

		}
	}
}
