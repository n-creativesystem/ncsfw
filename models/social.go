package models

type Social int

const (
	GOOGLE Social = iota + 1
	LINE
	Auth0
	Github
)
