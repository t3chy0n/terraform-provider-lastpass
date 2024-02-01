package terraform

import (
	"context"
	"fmt"
	"last-pass/client/dto"
	"last-pass/vault"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestAccResourceSecret_Basic(t *testing.T) {
	var secret dto.Account
	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    TestAccProviders,
		CheckDestroy: testAccResourceSecretDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccResourceSecretConfig_basic,
				Check: resource.ComposeTestCheckFunc(
					testAccResourceSecretExists("lastpass_secret.foobar", &secret),
					resource.TestCheckResourceAttr(
						"lastpass_secret.foobar", "name", "terraform-provider-lastpass resource basic test"),
					resource.TestCheckResourceAttr(
						"lastpass_secret.foobar", "username", "gopher"),
					resource.TestCheckResourceAttr(
						"lastpass_secret.foobar", "password", "hunter2"),
					resource.TestCheckResourceAttr(
						"lastpass_secret.foobar", "note", "FOO\nBAR\n"),
				),
			},
		},
	})
}

func testAccResourceSecretDestroy(s *terraform.State) error {
	c := TestAccProvider.Meta().(*vault.LastPassVault)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "lastpass_secret" {
			continue
		}
		orderID := rs.Primary.ID

		err := c.DeleteAccount(context.Background(), &dto.Account{Id: orderID})
		if err != nil {
			return err
		}
		secret, _ := c.GetAccount(context.Background(), rs.Primary.ID)
		if secret != nil {
			return fmt.Errorf("Secret still exists")
		}
	}
	return nil
}

func testAccResourceSecretExists(n string, secret *dto.Account) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No Secret ID is set")
		}
		c := TestAccProvider.Meta().(*vault.LastPassVault)
		account, err := c.GetAccount(context.Background(), rs.Primary.ID)
		if err != nil {
			return err
		}
		if account == nil {
			return fmt.Errorf("Secret not found")
		}
		*secret = *account
		return nil
	}
}

const testAccResourceSecretConfig_basic = `
resource "lastpass_secret" "foobar" {
    name = "terraform-provider-lastpass resource basic test"
    username = "gopher"
    password = "hunter2"
	note = <<EOF
FOO
BAR
EOF
}`
