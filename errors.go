package octohooks

type signatureInvalid string

func (s signatureInvalid) Error() string {
	return string(s)
}
