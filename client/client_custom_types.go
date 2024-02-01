package client

import (
	"context"
	"encoding/json"
	"errors"
	"last-pass/client/client_errors"
	"last-pass/client/dto"
	"net/http"
)

// Return all custom types defined by the user
func (lpassClient *LastPassClient) GetCustomTypes(ctx context.Context) ([]dto.CustomItemType, error) {
	loggedIn, err := lpassClient.IsLoggedIn(ctx)
	if err != nil {
		return nil, err
	}

	if !loggedIn {
		return nil, &client_errors.Authentication{"client not logged in"}
	}
	cookies := lpassClient.getSessionCookies()
	headers := http.Header{}
	headers.Add("x-csrf-token", lpassClient.Session.CSRFToken)

	rawRes, err := lpassClient.makeRequest(
		ctx,
		EndpointCustomTemplates,
		WithMethod("GET"),
		WithHeaders(headers),
		WithCookies(cookies),
	)

	var response []dto.CustomItemType

	if err := json.Unmarshal(rawRes, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// Create a new custom type for a user
func (lpassClient *LastPassClient) AddCustomType(ctx context.Context, customType *dto.CustomItemType) (*dto.CustomItemType, error) {

	loggedIn, err := lpassClient.IsLoggedIn(ctx)
	if err != nil {
		return nil, err
	}

	if !loggedIn {
		return nil, &client_errors.Authentication{"client not logged in"}
	}
	cookies := lpassClient.getSessionCookies()
	headers := http.Header{}
	headers.Add("x-csrf-token", lpassClient.Session.CSRFToken)

	rawRes, err := lpassClient.makeRequest(
		ctx,
		EndpointCustomTemplates,
		WithHeaders(headers),
		WithJsonBody(customType),
		WithCookies(cookies),
	)

	var response dto.CustomItemType

	if err := json.Unmarshal(rawRes, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

func (lpassClient *LastPassClient) DeleteCustomType(ctx context.Context, customType *dto.CustomItemType) error {

	if customType == nil {
		return errors.New("Custom type has to be defined")
	}
	if customType.Id == "" {
		return errors.New("Custom type id has to be defined")
	}
	loggedIn, err := lpassClient.IsLoggedIn(ctx)
	if err != nil {
		return err
	}

	if !loggedIn {
		return &client_errors.Authentication{"client not logged in"}
	}

	cookies := lpassClient.getSessionCookies()
	headers := http.Header{}
	headers.Add("x-csrf-token", lpassClient.Session.CSRFToken)

	_, err = lpassClient.makeRequest(
		ctx,
		EndpointCustomTemplates+"/"+customType.Id+"/delete",
		WithHeaders(headers),
		WithJsonBody(customType),
		WithCookies(cookies),
	)

	if err != nil {
		return err
	}
	return nil
}
