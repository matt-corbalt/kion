package console

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"

	"github.com/corbaltcode/kion/cmd/kion/config"
	"github.com/corbaltcode/kion/cmd/kion/util"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

func New(cfg *config.Config, keyCfg *config.KeyConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "console",
		Short: "Opens the AWS console",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg, keyCfg)
		},
	}

	cmd.Flags().StringP("account-id", "", "", "AWS account ID")
	cmd.Flags().StringP("cloud-access-role", "", "", "cloud access role")
	cmd.Flags().BoolP("print", "p", false, "print URL instead of opening a browser")
	cmd.Flags().BoolP("logout", "", false, "log out of existing AWS console session")
	cmd.Flags().StringP("region", "", "", "AWS Commercial region")
	cmd.Flags().StringP("govcloud-region", "", "", "AWS GovCloud region")
	cmd.Flags().StringP("session-duration", "", "1h", "duration of temporary credentials")

	return cmd
}

// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html
func run(cfg *config.Config, keyCfg *config.KeyConfig) error {
	accountID, err := cfg.StringErr("account-id")
	if err != nil {
		return err
	}
	cloudAccessRole, err := cfg.StringErr("cloud-access-role")
	if err != nil {
		return err
	}
	host, err := cfg.StringErr("host")
	if err != nil {
		return err
	}
	commercialRegion, err := cfg.StringErr("region")
	if err != nil {
		return err
	}

	govcloudRegion, err := cfg.StringErr("govcloud-region")
	if err != nil {
		return err
	}

	kion, err := util.NewClient(cfg, keyCfg)
	if err != nil {
		return err
	}

	accountInfo, err := kion.GetAccountByID(accountID)
	if err != nil {
		return err
	}

	awsEndpoint, region := "", ""
	// Account types: 1=commercial, 2=govcloud
	if accountInfo.AccountTypeID == 2 {
		region = govcloudRegion
		awsEndpoint = "amazonaws-us-gov.com"
	} else {
		region = commercialRegion
		awsEndpoint = "aws.amazon.com"
	}

	creds, err := kion.GetTemporaryCredentialsByCloudAccessRole(accountID, cloudAccessRole)
	if err != nil {
		return err
	}

	signinToken, err := util.GetAWSSigninToken(awsEndpoint, creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)
	if err != nil {
		return err
	}

	v := url.Values{}
	v.Add("Action", "login")
	v.Add("Issuer", fmt.Sprintf("https://%s/login", host))
	v.Add("Destination", fmt.Sprintf("https://%s.console.%s", region, awsEndpoint))
	v.Add("SigninToken", signinToken)
	signinUrl := fmt.Sprintf("https://signin.%s/federation?", awsEndpoint) + v.Encode()

	if cfg.Bool("print") {
		fmt.Println(signinUrl)
	} else if cfg.Bool("logout") {
		html := new(bytes.Buffer)
		err = logoutHtmlTemplate.Execute(html, signinUrl)
		if err != nil {
			return err
		}
		err = browser.OpenReader(html)
		if err != nil {
			return err
		}
	} else {
		err = browser.OpenURL(signinUrl)
		if err != nil {
			return err
		}
	}

	return nil
}

var logoutHtmlTemplate = template.Must(template.New("logout").Parse(`
	<body>
		<script>
			var iframe = document.createElement("iframe");
			iframe.style = "visibility: hidden;";
			iframe.src = "https://signin.aws.amazon.com/oauth?Action=logout";
			iframe.onload = (event) => {
				window.location = {{.}};
			};
			document.body.appendChild(iframe);
		</script>
	</body>`))
