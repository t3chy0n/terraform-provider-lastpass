package terraform

import (
	"context"
	"errors"
	"last-pass/client/dto"
	"last-pass/vault"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// DataSourceSecret describes our lastpass secret data source
func DataSourceSecret() *schema.Resource {
	return &schema.Resource{
		ReadContext: DataSourceSecretRead,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:     schema.TypeString,
				Required: false,
				Optional: true,
				Computed: true,
			},
			"name": {
				Type: schema.TypeString,

				Required: false,
				Optional: true,
				Computed: true,
			},
			"fullname": {
				Type: schema.TypeString,

				Required: false,
				Optional: true,
				Computed: true,
			},
			"username": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"last_modified_gmt": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"last_touch": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"group": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"note": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
			"custom_fields": {
				Type:      schema.TypeMap,
				Computed:  true,
				Sensitive: true,
			},
		},
	}
}

// DataSourceSecretRead reads resource from upstream/lastpass
func DataSourceSecretRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	vault := m.(*vault.LastPassVault)
	var diags diag.Diagnostics
	id, idIsOk := d.GetOk("id")
	if idIsOk {
		if _, err := strconv.Atoi(id.(string)); err != nil {
			err := errors.New("Not a valid Lastpass ID")
			return diag.FromErr(err)
		}
	}

	account, err := vault.GetAccount(ctx,
		func(acc *dto.Account) bool {
			return idIsOk && acc.Id == id.(string)

		},
		func(acc *dto.Account) bool {
			if fullname, ok := d.GetOk("fullname"); ok {

				return acc.FullName == fullname.(string)
			}
			return false

		},
		func(acc *dto.Account) bool {
			if name, ok := d.GetOk("name"); ok {

				return acc.Name == name.(string)
			}
			return false

		},
	)
	if err != nil {
		return diag.FromErr(err)
	}

	if account == nil {
		d.SetId("0")
		return diags
	}

	d.SetId(account.Id)
	d.Set("name", account.Name)
	d.Set("fullname", account.FullName)
	d.Set("username", account.Username)
	d.Set("password", account.Password)
	d.Set("last_modified_gmt", account.LastModifiedGMT)
	d.Set("last_touch", account.LastTouch)
	d.Set("group", account.Group)
	d.Set("url", account.Url)
	d.Set("note", account.Note)
	//d.Set("custom_fields", account.Cu)
	return diags
}
