package analysis

import (
	"context"
	"net/url"

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

func (g *GROUP) VerifyInlinePolicy(policyName *string, groupName *string, client *iam.Client, group *IAMGroup) {

	output, err := client.GetGroupPolicy(context.TODO(), &iam.GetGroupPolicyInput{PolicyName: policyName, GroupName: groupName})

	if err != nil {
		panic(err)
	}

	policyDocument, err := url.QueryUnescape(*output.PolicyDocument)

	if err != nil {
		panic(err)
	}

	// Proceed Only if we see any of the associated API action
	if isAction(APIListRegex, &policyDocument) {

		policy := IAMPolicy{
			PolicyName: *policyName,
		}

		processPolicy(&policyDocument, &policy)

		if policy.StatementIds != nil {
			group.InlinePolicies = append(group.InlinePolicies, policy)
		}

	}
}
