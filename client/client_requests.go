package client

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"last-pass/client/client_errors"
	"last-pass/client/dto"
	"last-pass/client/encryption"
	"last-pass/client/kdf"
	"last-pass/config"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PLUGIN_VERSION is a constant that represents the version of the extension being used.
// It's potentially utilized by LastPass to return data structured in a format compatible with this specific version.
// The version value "4.124.0" was taken by inspecting Chrome Extension at time of development.
const PLUGIN_VERSION = "4.124.0"

func (lpassClient *LastPassClient) getHashingIterations(email string) (int, error) {

	parameters := url.Values{
		"email": []string{strings.ToLower(email)},
	}

	res, err := lpassClient.makeRequest(context.Background(), EndpointIterations, WithUrlParams(parameters))
	if err != nil {
		fmt.Println("Problem with querying iterations:", err)
		return 0, err
	}
	var response int
	if err := json.Unmarshal(res, &response); err != nil {
		fmt.Println("Problem unmarshaling iterations response Ok:", err)

		return 0, err
	}

	return response, err
}

// Retrieves CSRF token from LastPass.
// Some endpoints utilizes this token for requests to prevent CSRF attacks
func (lpassClient *LastPassClient) getCSRFToken() (string, error) {
	cookies := lpassClient.getSessionCookies()
	rawRes, err := lpassClient.makeRequest(context.Background(), EndpointCSRF, WithCookies(cookies))
	if err != nil {
		return "", errors.New("Could not retrieve CSRF token. ")
	}

	return string(rawRes), nil
}

// Retrieves Encrypted attachement data from LastPass.
func (lpassClient *LastPassClient) GetAttachmentData(ctx context.Context, attachment *dto.Attachment, key []byte) (string, error) {
	parameters := url.Values{
		"getattach": []string{attachment.StorageKey},
	}
	cookies := lpassClient.getSessionCookies()
	rawRes, err := lpassClient.makeRequest(ctx, EndpointAttachment, WithUrlParams(parameters), WithCookies(cookies))
	if err != nil {
		return "", errors.New("Could not retrieve attachment data.")
	}
	decoded, err := encryption.Transform(string(rawRes),
		encryption.WithUnbase64(),
		encryption.WithAESDecrypt(key),
		encryption.WithUnbase64(),
	)

	return decoded, nil
}

// Authenticates a user. It will do out of band authentication, it only works well
// with 2fa providers which offer push notifications to mobile - LastPass and Duo Security
func (lpassClient *LastPassClient) login(username string) (*dto.Session, error) {

	if existingSession := config.GetCachedSession(username); existingSession != nil {
		return existingSession, nil
	}

	loginStartTime := time.Now()
	ctx := context.Background()

	parameters := url.Values{
		"xml":                  []string{"2"},
		"username":             []string{strings.ToLower(username)},
		"hash":                 []string{encryption.BytesToHex(lpassClient.KDFLoginKey)},
		"iterations":           []string{strconv.Itoa(lpassClient.iterations)},
		"includeprivatekeyenc": []string{"1"},
		"method":               []string{"cr"},
		"outofbandsupported":   []string{"1"},
		"sessonly":             []string{"0"},
		"uuid":                 []string{lpassClient.trustId},
		"hasplugin":            []string{"4.124.0"},
	}
	res, err := lpassClient.makeRequest(ctx, EndpointLogin, WithUrlParams(parameters))
	if err != nil {
		fmt.Println("Problem with login:", err)
	}

	response, err := xmlParse[dto.LastPassResponse[dto.Session]](res)

	const outOfBandRequired = "outofbandrequired"
	const multiFactorResponseFailed = "multifactorresponsefailed"

	if response == nil {
		return nil, fmt.Errorf("Couldn't login to Lastpass. %v (Response) %v", err, string(res))
	}
	if response.Error != nil && response.Error.Cause == outOfBandRequired {
		parameters.Set("outofbandrequest", "1")
		parameters.Set("outofbandretry", "0")
		parameters.Set("provider", response.Error.OutOfBandType)
		for i := 0; i < MaxLoginRetries; i++ {

			oobResp, err := lpassClient.makeRequest(ctx, EndpointLogin, WithUrlParams(parameters))
			if err != nil {
				return nil, err
			}
			response, err = xmlParse[dto.LastPassResponse[dto.Session]](oobResp)
			if response.Error != nil && response.Error.Cause == outOfBandRequired {
				if response.Error.Cause == multiFactorResponseFailed {
					return nil, &client_errors.Authentication{response.Error.Message}
				}
				if response.Error.Cause != outOfBandRequired {
					break
				} else {
					parameters.Set("outofbandretry", "1")
					parameters.Set("outofbandretryid", response.Error.RetryID)
				}
			}
			if response.Error == nil {
				break
			}

		}
		if response.Error != nil && response.Error.Cause == outOfBandRequired {
			return nil, &client_errors.Authentication{fmt.Sprintf(
				"didn't receive out-of-band approval within the last %.0f seconds",
				time.Since(loginStartTime).Seconds(),
			)}
		}
	}
	if response.Error != nil {
		fmt.Println()
		return nil, fmt.Errorf("Error during request. %s, errCode: %s", response.Error.Message, response.Error.Cause)
	}

	lpassClient.Session = response.Ok

	config.CacheSession(username, lpassClient.Session)

	if lpassClient.trust {

		session, err2 := lpassClient.AddTrustedDevice(ctx, lpassClient.trustId, lpassClient.trustLabel, response.Ok.Token)
		if err2 != nil {
			return session, err2
		}
	}

	if err != nil {
		return nil, err
	}

	decryptedPrivateKey, err := encryption.CipherDecryptPrivateKey(
		lpassClient.Session.PrivateKey,
		lpassClient.KDFDecryptionKey,
	)

	if err != nil {
		fmt.Println("Problem with decrypting private key:", err)
	}
	lpassClient.Session.PrivateKey = decryptedPrivateKey
	lpassClient.Session.KDFLoginKey = lpassClient.KDFLoginKey
	lpassClient.Session.KDFDecryptionKey = lpassClient.KDFDecryptionKey

	return response.Ok, err
}

func (lpassClient *LastPassClient) AddTrustedDevice(ctx context.Context, id string, label string, token string) (*dto.Session, error) {
	cookies := lpassClient.getSessionCookies()
	trustForm := url.Values{
		"token":      []string{token},
		"uuid":       []string{id},
		"trustlabel": []string{label},
	}

	if _, err := lpassClient.makeRequest(ctx, EndpointTrust, WithUrlParams(trustForm), WithCookies(cookies)); err != nil {
		return nil, err
	}
	return nil, nil
}

// Checks validity of Session
func (lpassClient *LastPassClient) IsLoggedIn(ctx context.Context) (bool, error) {
	if lpassClient.Session == nil || lpassClient.Session.Token == "" {
		return false, nil
	}

	parameters := url.Values{
		"method": []string{"cli"},
	}

	cookies := lpassClient.getSessionCookies()
	res, err := lpassClient.makeRequest(
		ctx,
		EndpointLoginCheck,
		WithUrlParams(parameters),
		WithCookies(cookies),
	)

	response, err := xmlParse[dto.LastPassResponse[dto.LoginCheck]](res)
	if err != nil {
		fmt.Println("Problem with validating current Session:", err)
		return false, err
	}

	return response.Ok.AcctsVersion != "", nil
}

// Return and parse encrypted vault data.
func (lpassClient *LastPassClient) GetBlob(ctx context.Context) (*Blob, error) {
	parameters := url.Values{
		"mobile":                              []string{"1"},
		"includesharedfolderformfillprofiles": []string{"1"},
		"includependingsharedfolders":         []string{"1"},
		"includelinkedsharedfolders":          []string{"1"},
		"requestsrc":                          []string{"cli"},
		"hasplugin":                           []string{PLUGIN_VERSION},
	}

	cookies := lpassClient.getSessionCookies()
	res, err := lpassClient.makeRequest(ctx, EndpointGetAccts, WithUrlParams(parameters), WithCookies(cookies))

	if err != nil {
		fmt.Println("Problem with retrieving accounts blob data:", err)
		return nil, err
	}

	return &Blob{Data: res}, nil
}

// Returns blob version
func (lpassClient *LastPassClient) GetBlobVersion(ctx context.Context) (int, error) {

	parameters := url.Values{
		"method": []string{"cli"},
	}
	cookies := lpassClient.getSessionCookies()
	res, err := lpassClient.makeRequest(ctx, EndpointLoginCheck, WithUrlParams(parameters), WithCookies(cookies))

	if err != nil {
		fmt.Println("Problem with retrieving accounts blob data:", err)
		return 0, err
	}
	var response int
	if err := xml.Unmarshal(res, &response); err != nil {
		fmt.Println("Problem unmarshaling blob version response Ok:", err)

		return 0, err
	}
	return response, nil
}

// Handles modification on account items. There exists an Application type, which seems to be not functioning well in lastpass,
// but this method handles this aswell. Although creating applications is not recommended.
func (lpassClient *LastPassClient) upsert(ctx context.Context, acct *dto.Account) (*dto.LastPassResponse[dto.AccountUpsertResponse], error) {

	loggedIn, err := lpassClient.IsLoggedIn(ctx)
	if err != nil {
		return nil, err
	}

	if !loggedIn {
		return nil, &client_errors.Authentication{"client not logged in"}
	}

	key := lpassClient.Session.KDFDecryptionKey

	if acct.IsShared() {
		key = acct.Share.Key
		if acct.Share.ReadOnly {
			return nil, fmt.Errorf("Account cannot be written to read-only shared folder %s.", acct.Share.Name)
		}
	}

	nameEncrypted, err := encryption.CipherAESEncrypt(acct.Name, key)
	if err != nil {
		return nil, err
	}
	userNameEncrypted, err := encryption.CipherAESEncrypt(acct.Username, key)
	if err != nil {
		return nil, err
	}
	passwordEncrypted, err := encryption.CipherAESEncrypt(acct.Password, key)
	if err != nil {
		return nil, err
	}
	groupEncrypted, err := encryption.CipherAESEncrypt(acct.Group, key)
	if err != nil {
		return nil, err
	}
	notesEncrypted, err := encryption.CipherAESEncrypt(acct.Note, key)
	if err != nil {
		return nil, err
	}
	hexName := encryption.BytesToHex([]byte(acct.Name))
	data := url.Values{
		"auto":        []string{"1"},
		"ajax":        []string{"1"},
		"extjs":       []string{"1"},
		"sessonly":    []string{"0"},
		"token":       []string{lpassClient.Session.Token},
		"method":      []string{"cr"},
		"requestsrc:": []string{"cr"},
		"pwprotect":   []string{"off"},
		"name":        []string{nameEncrypted},
		"hexName":     []string{hexName},
		"grouping":    []string{groupEncrypted},
		"hasplugin":   []string{PLUGIN_VERSION},
		"lpversion":   []string{PLUGIN_VERSION},
	}

	if acct.PwProtect {
		data.Set("pwprotect", "on")
	}
	if acct.Share != nil && acct.Share.Id != "" {
		data.Set("sharedfolderid", acct.Share.Id)
	}

	attachKey, attachKeyHex := kdf.GenerateAttachmentKey()
	attachKeyEncrypted, err := encryption.CipherAESEncrypt(attachKeyHex, key)

	if len(acct.Attachments) > 0 {
		data.Set("attachkey", attachKeyEncrypted)
	}

	for index, file := range acct.Attachments {

		attachNameEncrypted, err := encryption.CipherAESEncrypt(file.FileName, attachKey)
		dataEncrypted, err := encryption.CipherAESEncrypt(base64.StdEncoding.EncodeToString(file.Data), attachKey)

		if err != nil {
			return nil, errors.New("failed to serialize attachemenets for account")
		}
		data.Set(fmt.Sprintf("filename%d", index), attachNameEncrypted)
		data.Set(fmt.Sprintf("mimetype%d", index), file.MimeType)

		rand.Seed(time.Now().UnixNano())
		randomNumber := rand.Intn(100000)
		data.Set(fmt.Sprintf("attachid%d", index), strconv.Itoa(randomNumber))

		data.Set(fmt.Sprintf("attachbytes%d", index), dataEncrypted)
	}
	//NOTE: Application types seems not available trough frontends, also they dont render well in neither extension nor mobile app
	//NOTE: Seems that recommended way for storing something like env vars in single item, are custom items with predefined schema or form fields
	if acct.IsApp() {
		return lpassClient.upsertApplication(ctx, acct, data, key)
	}

	data.Set("url", hex.EncodeToString([]byte(acct.Url)))
	data.Set("aid", acct.Id)
	data.Set("extra", notesEncrypted)
	data.Set("username", userNameEncrypted)
	data.Set("password", passwordEncrypted)

	if acct.NoteType != "" {
		data.Set("notetype", acct.NoteType)
	}

	cookies := lpassClient.getSessionCookies()
	res, err := lpassClient.makeRequest(ctx, EndpointShowWebsite, WithUrlParams(data), WithCookies(cookies))

	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, &client_errors.AccountNotFound{acct.Id}
	}

	result, err := xmlParse[dto.LastPassResponse[dto.AccountUpsertResponse]](res)

	if (result.Ok != nil && result.Ok.Msg != "accountadded" && result.Ok.Msg != "accountupdated") || result.Error != nil {
		return nil, errors.New("failed to add/update account")
	}
	if result.Data != nil {
		acct.Id = result.Data.AccountId
	}

	fieldsResponse, err := lpassClient.updateAccountFieldsWithNewStructure(ctx, acct, key)
	if err != nil {
		return nil, err
	}
	if fieldsResponse != nil && fieldsResponse.Error != nil {
		return nil, errors.New(fmt.Sprintf("Failed adding fields for account %s", acct.Name))
	}
	return result, err
}

func (lpassClient *LastPassClient) updateAccountFields(ctx context.Context, acct *dto.Account, key []byte) (*dto.LastPassResponse[dto.AccountUpsertResponse], error) {
	cookies := lpassClient.getSessionCookies()
	fieldData := url.Values{
		"aid":    []string{acct.Id},
		"update": []string{"1"},
		"token":  []string{lpassClient.Session.Token},
		"method": []string{"cli"},
	}

	for _, field := range acct.Fields {

		valueEncrypted, err := encryption.CipherAESEncrypt(field.Value, key)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to encrypt %s field value", field.Name))
		}
		fieldData.Set(fmt.Sprintf("_%s", field.Name), valueEncrypted)
	}
	fieldsRawRes, err := lpassClient.makeRequest(ctx, EndpointFieldsIncremental, WithUrlParams(fieldData), WithCookies(cookies))
	println(fieldsRawRes)
	return nil, err
}

func (lpassClient *LastPassClient) updateAccountFieldsWithNewStructure(ctx context.Context, acct *dto.Account, key []byte) (*dto.LastPassResponse[dto.AccountUpsertResponse], error) {
	cookies := lpassClient.getSessionCookies()
	fieldData := url.Values{
		"aid":          []string{acct.Id},
		"ref":          []string{acct.Url},
		"updatefields": []string{"1"},
		"auto":         []string{"1"},
		"token":        []string{lpassClient.Session.Token},
		"method":       []string{"cli"},
	}

	var data string = ""
	for _, field := range acct.Fields {

		valueEncrypted, err := encryption.CipherAESEncrypt(field.Value, key)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("failed to encrypt %s field value", field.Name))
		}
		data = data + fmt.Sprintf("\t%s\t%s\t%s\n", field.Name, valueEncrypted, field.Type)

	}
	hashedData := encryption.BytesToHex([]byte(data))

	fieldData.Set("data", hashedData)
	fieldsRawRes, err := lpassClient.makeRequest(ctx, EndpointFields, WithUrlParams(fieldData), WithCookies(cookies))
	println(fieldsRawRes)
	return nil, err
}

// Add/update adds the application to LastPass.
// Since LastPass generates a new account/application ID, account.ID is ignored.
// If Client is not logged in, an *AuthenticationError is returned.
// To add an account to a shared folder, account.Share must be prefixed with "Shared-".
func (lpassClient *LastPassClient) upsertApplication(ctx context.Context, acct *dto.Account, accData url.Values, key []byte) (*dto.LastPassResponse[dto.AccountUpsertResponse], error) {

	accData.Set("ajax", "1")
	accData.Set("cmd", "updatelpaa")
	accData.Set("appname", acct.Application.Name)
	accData.Set("appid", acct.Id)
	for index, field := range acct.Fields {

		valueEncrypted, err := encryption.CipherAESEncrypt(field.Value, key)
		if err != nil {
			return nil, errors.New("failed to serialize fields for application")
		}
		accData.Set(fmt.Sprintf("fieldid%d", index), field.Name)
		accData.Set(fmt.Sprintf("fieldtype%d", index), field.Type)
		accData.Set(fmt.Sprintf("fieldvalue%d", index), valueEncrypted)
	}
	cookies := lpassClient.getSessionCookies()
	res, err := lpassClient.makeRequest(ctx, EndpointAddApplication, WithUrlParams(accData), WithCookies(cookies))
	if len(res) == 0 {
		return nil, &client_errors.AccountNotFound{acct.Id}
	}

	response, err := xmlParse[dto.LastPassResponse[dto.AccountUpsertResponse]](res)

	return response, err
}

// Add/update adds the account to LastPass.
// Since LastPass generates a new account ID, account.ID is ignored.
// When this method returns (without an error), account.ID is set to the newly generated account ID.
// If Client is not logged in, an *AuthenticationError is returned.
// To add an account to a shared folder, account.Share must be prefixed with "Shared-".
func (lpassClient *LastPassClient) Upsert(ctx context.Context, account *dto.Account) error {
	if account.Name == "" {
		return errors.New("account.Name must not be empty")
	}
	if account.Id == "" {
		account.Id = "0"
	}
	if account.IsApp() && account.Application.Id == "" {
		account.Application.Id = "0"
	}

	_, err := lpassClient.upsert(ctx, account)
	if err != nil {
		return err
	}
	return nil
}

// Update updates the account with the given account.ID.
// If account.ID does not exist in LastPass, an *AccountNotFoundError is returned.
// If Client is not logged in, an *AuthenticationError is returned.
//
// Updating an account within a shared folder is supported unless field account.Share itself is modified:
// To move an account to / from a shared folder, use Delete() and Add() functions instead.
func (lpassClient *LastPassClient) Update(ctx context.Context, account *dto.Account) error {
	result, err := lpassClient.upsert(ctx, account)
	if err != nil {
		return err
	}
	if (result.Ok != nil && result.Ok.Msg != "accountupdated") || result.Error != nil {
		return errors.New("failed to update account")
	}

	return nil
}

// Delete deletes the LastPass Account with the given account.ID.
// If account.ID does not exist in LastPass, an *AccountNotFoundError is returned.
// If Client is not logged in, an *AuthenticationError is returned.
//
// All Account fields other than account.ID and account.Share are ignored.
func (lpassClient *LastPassClient) Delete(ctx context.Context, acct *dto.Account) (*dto.LastPassResponse[dto.AccountUpsertResponse], error) {

	loggedIn, err := lpassClient.IsLoggedIn(ctx)
	if err != nil {
		return nil, err
	}

	if !loggedIn {
		return nil, &client_errors.Authentication{"client not logged in"}
	}

	data := url.Values{
		"extjs":  []string{"1"},
		"delete": []string{"1"},
		"token":  []string{lpassClient.Session.Token},
		"aid":    []string{acct.Id},
	}
	if acct.IsShared() && acct.Share.ReadOnly {

		return nil, fmt.Errorf("Account cannot be deleted from read-only shared folder %s.", acct.Share.Name)

	}

	if acct.Share != nil && acct.Share.Id != "" {
		data.Set("sharedfolderid", acct.Share.Id)
	}

	cookies := lpassClient.getSessionCookies()
	res, err := lpassClient.makeRequest(ctx, EndpointShowWebsite, WithUrlParams(data), WithCookies(cookies))

	if err != nil {
		return nil, err
	}

	if len(res) == 0 {
		return nil, &client_errors.AccountNotFound{acct.Id}
	}

	response, err := xmlParse[dto.LastPassResponse[dto.AccountUpsertResponse]](res)

	return response, err
}
