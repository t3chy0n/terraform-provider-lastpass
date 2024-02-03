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

// ResourceSecret describes our lastpass secret resource
func ResourceSecret() *schema.Resource {
	return &schema.Resource{
		CreateContext: ResourceSecretCreate,
		ReadContext:   ResourceSecretRead,
		UpdateContext: ResourceSecretUpdate,
		DeleteContext: ResourceSecretDelete,
		Importer: &schema.ResourceImporter{
			StateContext: ResourceSecretImporter,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"fullname": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"username": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"password": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Computed:  true,
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
				Optional: true,
				Computed: true,
			},
			"url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"note": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Computed:    true,
				Description: "The secret note content.",
			},
		},
	}
}

// ResourceSecretCreate is used to create a new resource and generate ID.
func ResourceSecretCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	vault := m.(*vault.LastPassVault)
	var diags diag.Diagnostics

	newAcc := &dto.Account{
		Name:     d.Get("name").(string),
		Group:    d.Get("group").(string),
		Username: d.Get("username").(string),
		Password: d.Get("password").(string),
		Url:      d.Get("url").(string),
		Note:     d.Get("note").(string),
	}
	err := vault.WriteAccount(ctx, newAcc)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(newAcc.Id)
	ResourceSecretRead(ctx, d, m)

	return diags
}

// ResourceSecretRead is used to sync the local state with the actual state (upstream/lastpass)
func ResourceSecretRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	vault := m.(*vault.LastPassVault)
	var diags diag.Diagnostics
	account, err := vault.GetAccountById(ctx, d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	if account == nil {
		d.SetId("")
		return nil
	}

	d.Set("name", account.Name)
	d.Set("fullname", account.FullName)
	d.Set("username", account.Username)
	d.Set("password", account.Password)
	d.Set("last_modified_gmt", account.LastModifiedGMT)
	d.Set("last_touch", account.LastTouch)
	d.Set("group", account.Group)
	d.Set("url", account.Url)
	d.Set("note", account.Note)

	return diags
}

// ResourceSecretUpdate is used to update our existing resource
func ResourceSecretUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	newAcc := &dto.Account{
		Name:     d.Get("name").(string),
		Group:    d.Get("group").(string),
		Username: d.Get("username").(string),
		Password: d.Get("password").(string),
		Url:      d.Get("url").(string),
		Note:     d.Get("note").(string),
		Id:       d.Id(),
	}

	vault := m.(*vault.LastPassVault)
	err := vault.WriteAccount(ctx, newAcc)
	if err != nil {
		return diag.FromErr(err)
	}
	return ResourceSecretRead(ctx, d, m)
}

// ResourceSecretDelete is called to destroy the resource.
func ResourceSecretDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	vault := m.(*vault.LastPassVault)
	var diags diag.Diagnostics
	err := vault.DeleteAccount(ctx, &dto.Account{Id: d.Id()})
	if err != nil {
		return diag.FromErr(err)
	}
	return diags
}

// ResourceSecretImporter is called to import an existing resource.
func ResourceSecretImporter(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	if _, err := strconv.Atoi(d.Id()); err != nil {
		err := errors.New("Not a valid Lastpass ID")
		return nil, err
	}
	vault := m.(*vault.LastPassVault)
	account, err := vault.GetAccountById(ctx, d.Id())
	if err != nil {
		return nil, err
	}
	if account == nil {
		var err = errors.New("ID not found")
		return nil, err
	}

	d.Set("name", account.Name)
	d.Set("fullname", account.FullName)
	d.Set("username", account.Username)
	d.Set("password", account.Password)
	d.Set("last_modified_gmt", account.LastModifiedGMT)
	d.Set("last_touch", account.LastTouch)
	d.Set("group", account.Group)
	d.Set("url", account.Url)
	d.Set("note", account.Note)

	return []*schema.ResourceData{d}, nil
}
