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
}`
