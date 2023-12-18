package dto

type Field struct {
	Name    string
	Type    string
	Value   string
	Hash    string
	Checked bool
}

// Fields used for custom templates
type CustomField struct {
	Name    string  `json:"text"`
	Type    string  `json:"type"`
	Value   *string `json:"value,omitempty"`
	Options *string `json:"options,omitempty"`
}

type CustomItemType struct {
	Id     string         `json:"id"`
	Title  string         `json:"title"`
	Fields []*CustomField `json:"fields"`
}

func ParseField(chunk *Chunk, key []byte) (*Field, error) {
	var field Field = Field{}
	var err error

	field.Name, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}
	field.Type, err = chunk.ReadPlainString()
	if err != nil {
		return nil, err
	}

	switch field.Type {
	case "email", "tel", "text", "password", "textarea":
		field.Value, err = chunk.ReadCryptString(key)
		if err != nil {
			return nil, err
		}
	default:
		field.Value, err = chunk.ReadPlainString()
		if err != nil {
			return nil, err
		}
	}
	field.Checked, err = chunk.ReadBoolean()
	if err != nil {
		return nil, err
	}

	return &field, nil
}
