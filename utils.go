package jwt

func Contains(s []string, y string) bool {
	for _, x := range s {
		if x == y {
			return true
		}
	}

	return false
}
