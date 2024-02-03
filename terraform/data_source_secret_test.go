package terraform

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"testing"
)

func TestAccDataSourceSecret_Basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: TestAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceSecretConfig_basic,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar", "name", "terraform-provider-lastpass datasource basic test"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar", "username", "gopher"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar", "password", "hunter2"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar", "note", "secret note"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar2", "note", "secret note"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar3", "note", "secret note"),
				),
			},
		},
	})
}

const testAccDataSourceSecretConfig_basic = `
resource "lastpass_secret" "foobar" {
    name = "terraform-provider-lastpass datasource basic test"
    username = "gopher"
    password = "hunter2"
    note = "secret note"
}
data "lastpass_secret" "foobar" {
    id = lastpass_secret.foobar.id
}
data "lastpass_secret" "foobar2" {
    name = lastpass_secret.foobar.name
}
data "lastpass_secret" "foobar3" {
    fullname = lastpass_secret.foobar.fullname
}

`

func TestAccDataSourceSecret_LookupByName(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: TestAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceSecretConfig_lookupbyname,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "name", "terraform-provider-lastpass datasource lookupbyname test"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "username", "gopher"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "password", "hunter2"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "note", "secret note"),
				),
			},
		},
	})
}

const testAccDataSourceSecretConfig_lookupbyname = `
resource "lastpass_secret" "foobar_lookup" {
    name = "terraform-provider-lastpass datasource lookupbyname test"
    username = "gopher"
    password = "hunter2"
    note = "secret note"
}

data "lastpass_secret" "foobar_lookup" {
    name = "terraform-provider-lastpass datasource lookupbyname test"
	depends_on = [
		lastpass_secret.foobar_lookup
	]
}

`

func TestAccDataSourceSecret_LookupByGroupAndName(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: TestAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccDataSourceSecretConfig_lookupbynameandgroup,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "name", "terraform-provider-lastpass"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "group", "testgroup"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "fullname", "testgroup\\terraform-provider-lastpass"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "username", "gopher"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "password", "hunter2"),
					resource.TestCheckResourceAttr(
						"data.lastpass_secret.foobar_lookup", "note", "secret note"),
				),
			},
		},
	})
}

const testAccDataSourceSecretConfig_lookupbynameandgroup = `
resource "lastpass_secret" "foobar_lookup" {
	group = "testgroup"
    name = "terraform-provider-lastpass"
    username = "gopher"
    password = "hunter2"
    note = "secret note"
}

data "lastpass_secret" "foobar_lookup" {
    name = "testgroup\\terraform-provider-lastpass"
	depends_on = [
		lastpass_secret.foobar_lookup
	]
}

`
