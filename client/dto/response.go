package dto

type ResultAttrData struct {
	AccountId string `xml:"aid,attr"`
	Action    string `xml:"action,attr"`
	Message   string `xml:"msg,attr"`
}
type LastPassResponse[TOkData any] struct {
	Data  *ResultAttrData       `xml:"result"`
	Ok    *TOkData              `xml:"ok"`
	Error *LastPassRequestError `xml:"error"`
}

type LastPassRequestError struct {
	Server                string `xml:"server,attr"`
	Message               string `xml:"message,attr"`
	Cause                 string `xml:"cause,attr"`
	RetryID               string `xml:"retryid,attr"`
	OutOfBandType         string `xml:"outofbandtype,attr"`
	EnabledProviders      string `xml:"enabledproviders,attr"`
	AllowMultiFactorTrust string `xml:"allowmultifactortrust,attr"`
	Capabilities          string `xml:"capadilities,attr"`
}
