package analysis

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func init() {
	RegisterAnalysis(&USER{})
}

type USER struct {
}

func (u *USER) Identify(client *iam.Client, identified *IdentifiedEntities) {

	userPaginator := iam.NewListUsersPaginator(client, &iam.ListUsersInput{}, func(po *iam.ListUsersPaginatorOptions) {
		po.Limit = 100
	})

	for userPaginator.HasMorePages() {

		output, err := userPaginator.NextPage(context.TODO())

		if err != nil {
			panic(err)
		}
		for start := 0; start < len(output.Users); start += BatchSize {
			end := start + BatchSize

			if end > len(output.Users) {
				end = len(output.Users)
			}

			userNames := output.Users[start:end]

			wg.Add(1)
			go func(userNames *[]types.User) {
				defer wg.Done()
				u.ProcessBatch(userNames, client, identified)
			}(&userNames)

		}
		wg.Wait()
	}
}

func (u *USER) ProcessBatch(users *[]types.User, client *iam.Client, identified *IdentifiedEntities) {

	managedPolicies := []IAMPolicy{}

	for _, user := range *users {
		usr := IAMUser{
			Name: *user.UserName,
		}
		u.ListPolicies(user.UserName, client, &usr, &managedPolicies)
		if usr.InlinePolicies != nil {
			mu.Lock()
			identified.Users = append(identified.Users, usr)
			mu.Unlock()
		}

	}

	if managedPolicies != nil {
		mu.Lock()
		identified.ManagedPolicies = append(identified.ManagedPolicies, managedPolicies...)
		mu.Unlock()
	}
}

func (u *USER) ListPolicies(userName *string, client *iam.Client, user *IAMUser, managedPolicies *[]IAMPolicy) {

	inlinePolicies, err := client.ListUserPolicies(context.TODO(), &iam.ListUserPoliciesInput{UserName: userName})

	if err != nil {
		panic(err)
	}

	attachedPolicies, err := client.ListAttachedUserPolicies(context.TODO(), &iam.ListAttachedUserPoliciesInput{UserName: userName})

	if err != nil {
		panic(err)
	}

	if inlinePolicies != nil {
		for _, policyName := range inlinePolicies.PolicyNames {
			u.VerifyInlinePolicy(&policyName, userName, client, user)
		}
	}

	if attachedPolicies != nil {
		for _, policy := range attachedPolicies.AttachedPolicies {
			VerifyAttachedPolicy(policy.PolicyArn, client, managedPolicies)
		}
	}
}

func (u *USER) VerifyInlinePolicy(policyName *string, userName *string, client *iam.Client, user *IAMUser) bool {

	policy := IAMPolicy{
		PolicyName: *policyName,
	}

	output, err := client.GetUserPolicy(context.TODO(), &iam.GetUserPolicyInput{PolicyName: policyName, UserName: userName})

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
		user.InlinePolicies = append(user.InlinePolicies, policy)
		return true
	}

	return false
}

// func (u *USER) VerifyAttachedPolicy(policyArn *string, client *iam.Client, entity *IdentifiedEntity) {

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
