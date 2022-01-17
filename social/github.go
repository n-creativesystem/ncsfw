package social

type SocialGithub struct {
	*SocialBase
	allowedOrganizations []string
	apiUrl               string
	teamIds              []int
}

type GithubTeam struct {
	Id           int    `json:"id"`
	Slug         string `json:"slug"`
	URL          string `json:"html_url"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}
