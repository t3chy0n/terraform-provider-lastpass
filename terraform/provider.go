package terraform

import (
	"context"
	"last-pass/client"
	"last-pass/client/kdf"
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
				Description: "Lastpass username/e-email",
				DefaultFunc: schema.EnvDefaultFunc("LASTPASS_USER", nil),
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "Lastpass password",
				DefaultFunc: schema.EnvDefaultFunc("LASTPASS_PASSWORD", nil),
			},
			"trust_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Sensitive:   true,
				Description: "Trusted id, associated with a that will be trusted after successful login. When empty, random id will be generated.",
				DefaultFunc: func() (interface{}, error) {
					return kdf.CalculateTrustID(true)
				},
			},
			"trust_label": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Trusted label, associated with a that will be trusted after successful login",
				DefaultFunc: func() (interface{}, error) {
					return "Terraform client", nil
				},
			},
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	logger := log.New(os.Stderr, "LastPass Client Test", log.LstdFlags)

	var lastPassClient, err = client.NewClient(
		d.Get("username").(string),
		d.Get("password").(string),
		client.WithTrustId(d.Get("trust_id").(string)),
		client.WithTrustLabel(d.Get("trust_label").(string)),
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
