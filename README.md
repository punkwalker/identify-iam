## Identify Missing IAM Action

This project is a CLI tool to identify which AWS IAM entity (Role, User, group) is missing specified IAM permisions.

### Description
The tool will scan all the IAM entities in an AWS account and display IAM entities with missing required permission as shown below.

### Output
```
users:
- name: punuser1kwalker
  decision: implicitDeny
  deniedbypolicies: []
roles:
- name: AllowECSWithoutTag
  decision: implicitDeny
  deniedbypolicies: []
- name: ecsInstanceRole
  decision: explicitDeny
  deniedbypolicies:
  - arn:aws:iam::11111111111:policy/DenyTagResource
groups:
- name: group1
  decision: implicitDeny
  deniedbypolicies: []
```

### Usage
```
Usage: ecs-tag-action-identify [OPTIONS]
  -api-regex string
        API Regexp to match related actions (default "(ecs:(Create(CapacityProvider|Cluster|Service|TaskSet)|Register(ContainerInstance|TaskDefinition)|(Run|Start)Task))|(ecs:(Create\\*|Register\\*|Run\\*|Start*))")
  -concurrancy int
        Number of Concurrent Batches (default 10)
  -help
        Print Usage
  -new-api string
        New API Action to identify (default "ecs:TagResource")
  -o string
        Output format. yaml or json (default "yaml")
```

## Installation
### Running Locally
If installing locally, make sure golang v1.20 is installed and AWS CLI is configured with [IAMReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/IAMReadOnlyAccess.html) or equivalent permissions. 
```
go install github.com/punkwalker/identify-iam/cmd/ecs-tag-action-identify@latest
```
### Inside docker container
To use the tool inside docker container, execute following commands.
```
# Using local AWS Credentials directory
docker run -it --net=host \
  -v ~/.aws/:/root/.aws/ \
  golang:1.20.13-alpine \
  sh -c "go install github.com/punkwalker/identify-iam/cmd/ecs-tag-action-identify@latest && ecs-tag-action-identify"

# Using AWS Environment Variables for User
docker run -it --net=host \
  -e AWS_ACCESS_KEY_ID=<Access-Key> \
  -e AWS_SECRET_ACCESS_KEY=<Secret-Key>
  golang:1.20.13-alpine \
  sh -c "go install github.com/punkwalker/identify-iam/cmd/ecs-tag-action-identify@latest && ecs-tag-action-identify"

# Using Environment Variables for Assumed Role Credentials
docker run -it --net=host \
  -e AWS_ACCESS_KEY_ID=<Access-Key> \
  -e AWS_SECRET_ACCESS_KEY=<Secret-Key> \
  -e AWS_SESSION_TOKEN=<Session-Token> \
  golang:1.20.13-alpine \
  sh -c "go install github.com/punkwalker/identify-iam/cmd/ecs-tag-action-identify@latest && ecs-tag-action-identify"
```
## Use Case
Following ECS API Calls now require to have `ecs:tagResource` IAM permission for successfull functioning.
```
    "ecs:CreateCapacityProvider",
    "ecs:CreateCluster",
    "ecs:CreateService",
    "ecs:CreateTaskSet",
    "ecs:RegisterContainerInstance",
    "ecs:RegisterTaskDefinition",
    "ecs:RunTask",
    "ecs:StartTask"
```
If the associated policies of IAM entity does not allow `ecs:tagResource` action, then above API calls will fail with ***AccessDenied*** error.
