package cloud

import (
	"context"

	"github.com/adalundhe/micron/config"
	micronAWS "github.com/adalundhe/micron/provider/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)


type AWSLambdaProvider interface {
	TriggerLambda(ctx context.Context, req *InvokeLambdaRequest) (*lambda.InvokeOutput, error)
}


type AWSLambdaProviderImpl struct {
	client *lambda.Client
	triggerTypes []string
}

type AWSLambdaOpts struct {
	ConfigOpts []func(*awsconfig.LoadOptions) error
	LambdaConfigOpts []func(*lambda.Options)
}

type InvokeLambdaRequest struct {
	Name string
	SerializedContext string
	TriggerType string
	Payload []byte

}

func includes(val string, vals []string) bool {
	for _, valid := range vals {
		if val == valid {
			return true
		}
	}

	return false
}

func NewAWSLambda(ctx context.Context, cfg *config.Config, opts AWSLambdaOpts) (AWSLambdaProvider, error) {
	awsProvider, err := micronAWS.NewAwsProvider(ctx, cfg.Providers.Aws[cfg.Api.Env], opts.ConfigOpts...)
	if err != nil {
		return nil, err
	}

	awsCfg, err := awsProvider.GetConfig(ctx)
	if err != nil {
		return nil, err
	}

	client := lambda.NewFromConfig(awsCfg, opts.LambdaConfigOpts...)

	return &AWSLambdaProviderImpl{
		client: client,
		triggerTypes: []string{"RequestResponse", "Event", "DryRun"},
	}, nil
}


func (l *AWSLambdaProviderImpl) TriggerLambda(ctx context.Context, req *InvokeLambdaRequest) (*lambda.InvokeOutput, error) {

	context := &req.SerializedContext
	if req.SerializedContext == "" {
		context = nil
	}

	if !includes(req.TriggerType, l.triggerTypes) {
		req.TriggerType = "RequestResponse"
	}

	return l.client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName: &req.Name,
		ClientContext: context,
		InvocationType: types.InvocationType(req.TriggerType),
		Payload: req.Payload,
	})
}