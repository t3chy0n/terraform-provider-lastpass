package terraform

import (
	"context"
	"last-pass/client"
	"last-pass/vault"
	"log"
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider config
type config struct {
	Username string
	Password string
}

// Provider is the root of the lastpass provider
func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"lastpass_secret": ResourceSecret(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"lastpass_secret": DataSourceSecret(),
		},
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Lastpass login e-mail",
				DefaultFunc: schema.EnvDefaultFunc("LASTPASS_USER", nil),
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Lastpass login password",
				DefaultFunc: schema.EnvDefaultFunc("LASTPASS_PASSWORD", nil),
			},
			//"trust_id": {
			//	Type:        schema.TypeString,
			//	Required:    true,
			//	Sensitive:   true,
			//	Description: "Trusted id, associated with a that will be trusted after successful login",
			//	DefaultFunc: func() (interface{}, error) {
			//		return "ASDASD", nil
			//	},
			//	//schema.EnvDefaultFunc("LASTPASS_TRUST_ID", nil),
			//},
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	logger := log.New(os.Stderr, "LastPass Client"+d.Get("username").(string)+d.Get("password").(string), log.LstdFlags)

	var lastPassClient, err = client.NewClient(
		d.Get("username").(string),
		d.Get("password").(string),
		client.WithLogger(logger),
		client.WithTrust(),
	)

	var lpassVault = vault.NewLastPassVault(
		lastPassClient,
	)

	if err != nil {
		diags = diag.FromErr(err)
	}

	return lpassVault, diags
}
