package analysis

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func init() {
	RegisterAnalysis(&GROUP{})
}

type GROUP struct {
}

func (g *GROUP) Identify(client *iam.Client, identified *IdentifiedEntities) {

	groupPaginator := iam.NewListGroupsPaginator(client, &iam.ListGroupsInput{}, func(po *iam.ListGroupsPaginatorOptions) {
		po.Limit = 100
	})

	for groupPaginator.HasMorePages() {

		output, err := groupPaginator.NextPage(context.TODO())

		if err != nil {
			panic(err)
		}
		for start := 0; start < len(output.Groups); start += BatchSize {

			end := start + BatchSize

			if end > len(output.Groups) {
				end = len(output.Groups)
			}

			groupNames := output.Groups[start:end]

			wg.Add(1)
			go func(groupNames *[]types.Group) {
				defer wg.Done()
				g.ProcessBatch(groupNames, client, identified)
			}(&groupNames)

		}
		wg.Wait()
	}
}

func (g *GROUP) ProcessBatch(groups *[]types.Group, client *iam.Client, identified *IdentifiedEntities) {
	managedPolicies := []IAMPolicy{}

	for _, group := range *groups {
		grp := IAMGroup{
			Name: *group.GroupName,
		}
		g.ListPolicies(group.GroupName, client, &grp, &managedPolicies)
		if grp.InlinePolicies != nil {
			mu.Lock()
			identified.Groups = append(identified.Groups, grp)
			mu.Unlock()
		}

	}

	if managedPolicies != nil {
		mu.Lock()
		identified.ManagedPolicies = append(identified.ManagedPolicies, managedPolicies...)
		mu.Unlock()
	}
}

func (g *GROUP) ListPolicies(groupName *string, client *iam.Client, group *IAMGroup, managedPolicies *[]IAMPolicy) {

	inlinePolicies, err := client.ListGroupPolicies(context.TODO(), &iam.ListGroupPoliciesInput{GroupName: groupName})

	if err != nil {
		panic(err)
	}

	attachedPolicies, err := client.ListAttachedGroupPolicies(context.TODO(), &iam.ListAttachedGroupPoliciesInput{GroupName: groupName})

	if err != nil {
		panic(err)
	}

	if inlinePolicies != nil {
		for _, policyName := range inlinePolicies.PolicyNames {
			g.VerifyInlinePolicy(&policyName, groupName, client, group)
		}
	}

	if attachedPolicies != nil {
		for _, policy := range attachedPolicies.AttachedPolicies {
			VerifyAttachedPolicy(policy.PolicyArn, client, managedPolicies)
		}
	}
}

func (g *GROUP) VerifyInlinePolicy(policyName *string, groupName *string, client *iam.Client, group *IAMGroup) bool {
	policy := IAMPolicy{
		PolicyName: *policyName,
	}

	output, err := client.GetGroupPolicy(context.TODO(), &iam.GetGroupPolicyInput{PolicyName: policyName, GroupName: groupName})

	if err != nil {
		panic(err)
	}
	p := parseDocument(output.PolicyDocument)

	if err != nil {
		panic(err)
	}

	if err != nil {
		panic(err)
	}

	for _, statement := range p.Statements.Values() {
		actions := statement.Action.Values()
		effect := statement.Effect

		if isECSAction(strings.Join(actions, ",")) && effect == "Allow" {
			policy.StatementIds = append(policy.StatementIds, statement.Sid)
		}
	}

	if policy.StatementIds != nil {
		group.InlinePolicies = append(group.InlinePolicies, policy)
		return true
	}

	return false
}

// func (g *GROUP) VerifyAttachedPolicy(policyArn *string, client *iam.Client, entity *IdentifiedEntity) {

// 	if isAWSManaged(policyArn) {
// 		return
// 	}

// 	policy, err := client.GetPolicy(context.TODO(), &iam.GetPolicyInput{PolicyArn: policyArn})

// 	AttachedPolicy := IAMPolicy{
// 		PolicyName: *policy.Policy.PolicyName,
// 	}

// 	if err != nil {
// 		panic(err)
// 	}

// 	policyVersion, err := client.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{PolicyArn: policyArn, VersionId: policy.Policy.DefaultVersionId})

// 	if err != nil {
// 		panic(err)
// 	}

// 	p := parseDocument(policyVersion.PolicyVersion.Document)

// 	for _, statement := range p.Statements.Values() {
// 		actions := statement.Action.Values()
// 		effect := statement.Effect
// 		if isECSAction(strings.Join(actions, ",")) && effect == "Allow" {
// 			AttachedPolicy.StatementIds = append(AttachedPolicy.StatementIds, statement.Sid)
// 		}
// 	}

// 	if AttachedPolicy.StatementIds != nil {
// 		entity.Policies = append(entity.Policies, AttachedPolicy)
// 	}
// }
