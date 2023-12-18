package client_errors

// AccountNotFound indicates that no account with AccountNotFound.ID exists on LastPass.
type AccountNotFound struct {
	// account ID that does not exist
	ID string
}

func (e *AccountNotFound) Error() string {
	return "could not find LastPass account with ID=" + e.ID
}

// Authentication indicates that the Client is not logged in.
type Authentication struct {
	Msg string
}

func (e *Authentication) Error() string {
	return e.Msg
}
