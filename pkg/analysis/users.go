package analysis

import (
	"context"
	"net/url"

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

func (u *USER) VerifyInlinePolicy(policyName *string, userName *string, client *iam.Client, user *IAMUser) {

	output, err := client.GetUserPolicy(context.TODO(), &iam.GetUserPolicyInput{PolicyName: policyName, UserName: userName})

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
			user.InlinePolicies = append(user.InlinePolicies, policy)
		}

	}
}
