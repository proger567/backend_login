package testgenerate_backend_login

type Credential struct {
	UserName string `json:"user_name"`
	Password string `json:"password"`
}

type RefreshToken struct {
	Refreshuuid string `json:"refreshuuid"`
}

type TokenLogin struct {
	User        string `json:"user"`
	Jwttoken    string `json:"jwttoken"`
	Refreshuuid string `json:"refreshuuid"`
	Role        string `json:"role"`
}

type AccessDetails struct {
	UserName string
	UserRole string
}

type TokenDetails struct {
	AccessToken  string
	AccessUuid   string
	AtExpires    int64
	RandomString string
	Fingeprint   string
	RefreshUuid  string
	RtExpires    int64
}
