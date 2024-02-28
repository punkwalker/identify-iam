package analysis

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/micahhausler/aws-iam-policy/policy"
)

type Utils struct {
}

func parseDocument(policyDocument *string) *policy.Policy {

	var p policy.Policy

	err := json.Unmarshal([]byte(*policyDocument), &p)

	if err != nil {
		panic(err)
	}

	return &p

}

func isAction(actionsRegex *regexp.Regexp, policyDocument *string) bool {
	return actionsRegex.MatchString(*policyDocument)
}

func processPolicy(policyDocument *string, policies *[]string, policyName *string) {

	p := parseDocument(policyDocument)
	statements := []policy.Statement{}

	for _, statement := range p.Statements.Values() {

		newStatement := policy.Statement{}

		if statement.Action != nil {
			actions := statement.Action.Values()

			newStatement = policy.Statement{
				Action:   policy.NewStringOrSlice(false, actions...),
				Resource: policy.NewStringOrSlice(true, "*"),
				Sid:      statement.Sid,
				Effect:   statement.Effect,
			}
		} else if statement.NotAction != nil {
			actions := statement.NotAction.Values()

			newStatement = policy.Statement{
				Action:   policy.NewStringOrSlice(false, actions...),
				Resource: policy.NewStringOrSlice(true, "*"),
				Sid:      statement.Sid,
				Effect:   statement.Effect,
			}
		}

		statements = append(statements, newStatement)
	}

	if len(statements) != 0 {

		customPolicy := policy.Policy{
			Id:         *policyName,
			Statements: policy.NewStatementOrSlice(statements...),
			Version:    p.Version,
		}

		policyBytes, err := json.Marshal(customPolicy)

		if err != nil {
			panic(err)
		}

		policyString := string(policyBytes)

		*policies = append(*policies, policyString)
	}

}

func VerifyAttachedPolicy(policyArn *string, entity *Entity, client *iam.Client) {

	policyOut, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{PolicyArn: policyArn})

	if err != nil {
		panic(err)
	}

	policyVersion, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{PolicyArn: policyArn, VersionId: policyOut.Policy.DefaultVersionId})

	if err != nil {
		panic(err)
	}
	policyDocument, err := url.QueryUnescape(*policyVersion.PolicyVersion.Document)
	if err != nil {
		panic(err)
	}

	processPolicy(&policyDocument, &entity.Policies, policyArn)

}

func addEntity(entity *Entity, idEntity IdentifiedEntity, cfg *Configuration) {

	mu := Configuration.NewMutex(Configuration{})
	switch {
	case entity.Type == "Role":
		mu.Lock()
		cfg.Identified.Roles = append(cfg.Identified.Roles, idEntity)
		mu.Unlock()
	case entity.Type == "User":
		mu.Lock()
		cfg.Identified.Users = append(cfg.Identified.Users, idEntity)
		mu.Unlock()
	case entity.Type == "Group":
		mu.Lock()
		cfg.Identified.Groups = append(cfg.Identified.Groups, idEntity)
		mu.Unlock()
	default:
		panic("Invalid Enitity Type")
	}
}

func QueueWorker(cfg *Configuration, opts *Options) {
	mu := Configuration.NewMutex(Configuration{})
	for entity := range cfg.Queue {
		idEntity := IdentifiedEntity{
			Name:             entity.Name,
			DeniedByPolicies: []string{},
		}

		policies := strings.Join(entity.Policies, ",")
		if isAction(opts.APIregex, &policies) {

			out2, err := cfg.IAMClient.SimulateCustomPolicy(context.TODO(), &iam.SimulateCustomPolicyInput{
				ActionNames:     opts.NewAction,
				PolicyInputList: entity.Policies,
			})

			if err != nil {
				panic(err)
			}

			for _, result := range out2.EvaluationResults {

				if result.EvalDecision != types.PolicyEvaluationDecisionTypeAllowed {
					idEntity.Decision = result.EvalDecision

					for _, match := range result.MatchedStatements {

						policyIndex, err := strconv.Atoi(strings.Split(*match.SourcePolicyId, ".")[1])

						if err != nil {
							panic(err)
						}

						p := policy.Policy{}
						err = json.Unmarshal([]byte(entity.Policies[policyIndex-1]), &p)

						if err != nil {
							panic(err)
						}

						idEntity.DeniedByPolicies = append(idEntity.DeniedByPolicies, p.Id)

						cfg.PolicyDecisionCache[p.Id] = string(idEntity.Decision)

					}

					addEntity(&entity, idEntity, cfg)

				} else {

					idEntity.Decision = result.EvalDecision

					for _, match := range result.MatchedStatements {

						policyIndex, err := strconv.Atoi(strings.Split(*match.SourcePolicyId, ".")[1])

						if err != nil {
							panic(err)
						}

						p := policy.Policy{}
						err = json.Unmarshal([]byte(entity.Policies[policyIndex-1]), &p)

						if err != nil {
							panic(err)
						}

						mu.Lock()
						cfg.PolicyDecisionCache[p.Id] = string(idEntity.Decision)
						mu.Unlock()

					}

				}

			}

		}
	}
}
