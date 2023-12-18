package dto

type NoteType string

const (
	NOTE_TYPE_NONE    = ""
	NOTE_TYPE_GENERIC = "Generic"
	NOTE_TYPE_AMEX    = "Amex"
	NOTE_TYPE_BANK    = "Bank"
	NOTE_TYPE_CREDIT
	NOTE_TYPE_DATABASE = "Database"
	NOTE_TYPE_DRIVERS_LICENSE
	NOTE_TYPE_EMAIL
	NOTE_TYPE_HEALTH_INSURANCE
	NOTE_TYPE_IM
	NOTE_TYPE_INSURANCE
	NOTE_TYPE_MASTERCARD
	NOTE_TYPE_MEMBERSHIP
	NOTE_TYPE_PASSPORT
	NOTE_TYPE_SERVER = "Server"
	NOTE_TYPE_SOFTWARE_LICENSE
	NOTE_TYPE_SSH_KEY = "SSH Key"
	NOTE_TYPE_SSN
	NOTE_TYPE_VISA
	NOTE_TYPE_WIFI = "Wifi"
)

type NoteTemplate struct {
	NoteType  NoteType
	Name      string
	Shortname string
	Fields    []string
}

type AccountSecretNoteFields struct {
	Notes string
}

type AccountServerFields struct {
	Hostname string
	Username string
	Password string
	Notes    string
}

type AccountDatabaseFields struct {
	Type     string
	Hostname string
	Port     string
	Database string
	Username string
	Password string
	SID      string
	Alias    string
	Notes    string
}

type AccountSshFields struct {
	BitStrength string
	Format      string
	Passphrase  string
	Database    string
	PrivateKey  string
	PublicKey   string
	Hostname    string
	Date        string
	Notes       string
}
