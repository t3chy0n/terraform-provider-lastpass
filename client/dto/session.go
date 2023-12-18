package dto

type Session struct {
	KDFLoginKey      []byte
	KDFDecryptionKey []byte
	UID              string `xml:"uid,attr"`
	SessionID        string `xml:"sessionid,attr"`
	Token            string `xml:"token,attr"`
	CSRFToken        string
	PrivateKey       []byte `xml:"privatekeyenc,attr"`
}

type LoginCheck struct {
	AcctsVersion string `xml:"accts_version,attr"`
}
