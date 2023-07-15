package firefox

import (
	"fmt"
	"hash/fnv"
	"net/url"
	"os/exec"
	"strings"

	"github.com/corbaltcode/kion/cmd/kion/config"
	"github.com/corbaltcode/kion/cmd/kion/util"
	"github.com/spf13/cobra"
)

func New(cfg *config.Config, keyCfg *config.KeyConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firefox",
		Short: "Opens the AWS console in an account specific Firefox container",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg, keyCfg)
		},
	}

	cmd.Flags().StringP("account-id", "", "", "AWS account ID")
	cmd.Flags().StringP("cloud-access-role", "", "", "cloud access role")
	cmd.Flags().BoolP("print", "p", false, "print URL instead of opening a browser")
	cmd.Flags().StringP("region", "", "", "AWS region")
	cmd.Flags().StringP("session-duration", "", "1h", "duration of temporary credentials")

	// container customizability
	cmd.Flags().StringP("container-name", "", "", "name of the Firefox container")
	cmd.Flags().StringP("container-color", "", "", "color of the Firefox container; this is ignore if the container already exist by name")

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
	region, err := cfg.StringErr("region")
	if err != nil {
		return err
	}

	kion, err := util.NewClient(cfg, keyCfg)
	if err != nil {
		return err
	}

	creds, err := kion.GetTemporaryCredentialsByCloudAccessRole(accountID, cloudAccessRole)
	if err != nil {
		return err
	}

	signinToken, err := util.GetAWSSigninToken(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)
	if err != nil {
		return err
	}

	v := url.Values{}
	v.Add("Action", "login")
	v.Add("Issuer", fmt.Sprintf("https://%s/login", host))
	v.Add("Destination", fmt.Sprintf("https://%s.console.aws.amazon.com", region))
	v.Add("SigninToken", signinToken)
	signinUrl := "https://signin.aws.amazon.com/federation?" + v.Encode()

	firefoxContainerUrl, err := buildFirefoxContainerUrl(cfg, signinUrl, accountID)
	if err != nil {
		return err
	}

	if cfg.Bool("print") {
		fmt.Println(firefoxContainerUrl)
	} else {
		cmd := exec.Command("firefox", firefoxContainerUrl)
		_, err := cmd.Output()
		if err != nil {
			return err
		}
	}

	return nil
}

func buildFirefoxContainerUrl(cfg *config.Config, signinUrl string, accountID string) (string, error) {
	// add-on reference: https://github.com/honsiorovskyi/open-url-in-container/tree/1.0.3
	//
	// format: ext+container:name=MyContainer&color=orange&icon=fruit&url=https://mozilla.org&pinned=true

	// ampersand (&) needs to be encoded since it is the delimiter to other parameters in the protocol
	signinUrl = strings.ReplaceAll(signinUrl, "&", "%26")

	name, color := getContainerNameAndColor(cfg, accountID)
	name = url.QueryEscape(name)
	name = strings.ReplaceAll(name, "&", "%26")

	containerUrl := "ext+container:"
	containerUrl += fmt.Sprintf("name=%s&", name)
	containerUrl += fmt.Sprintf("color=%s&", color)
	containerUrl += fmt.Sprintf("url=%s", signinUrl)

	return containerUrl, nil
}

func getContainerNameAndColor(cfg *config.Config, accountID string) (string, string) {
	// set default values
	containerName := accountID
	containerColor := getDefaultContainerColor(accountID)

	// check if the config map has the name and color of the container
	containersCfg := cfg.StringMap(fmt.Sprintf("firefox-containers.%s", accountID))
	if containersCfg != nil {
		if name, ok := containersCfg["name"]; ok {
			containerName = name
		}
		if color, ok := containersCfg["color"]; ok {
			containerColor = color
		}
	}

	// override if the cli args are specified
	containerNameArg, err := cfg.StringErr("container-name")
	if err == nil && len(containerNameArg) > 0 {
		containerName = containerNameArg
	}
	containerColorArg, err := cfg.StringErr("container-color")
	if err == nil && len(containerColorArg) > 0 {
		containerColor = containerColorArg
	}

	return containerName, containerColor
}

func getDefaultContainerColor(accountID string) string {
	// firefox containers only supports a limited number of colors
	// https://github.com/mozilla/multi-account-containers/blob/f20688c453a337e0a695eee53c2a087e35b1d7bd/src/js/popup.js#L1868
	colors := []string{"blue", "turquoise", "green", "yellow", "orange", "red", "pink", "purple"}
	hashVal := hash(accountID)
	colorsLen := uint32(len(colors))
	idx := hashVal % colorsLen
	return colors[idx]
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}
