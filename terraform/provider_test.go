package terraform

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var TestAccProviders map[string]*schema.Provider
var TestAccProvider *schema.Provider

func init() {
	TestAccProvider = Provider()
	TestAccProviders = map[string]*schema.Provider{
		"lastpass": TestAccProvider,
	}
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func testAccPreCheck(t *testing.T) {
	if v := os.Getenv("LASTPASS_USER"); v == "" {
		t.Fatal("LASTPASS_USER must be set for acceptance tests")
	}
	if v := os.Getenv("LASTPASS_PASSWORD"); v == "" {
		t.Fatal("LASTPASS_PASSWORD must be set for acceptance tests")
	}
}
