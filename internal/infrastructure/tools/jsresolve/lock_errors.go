package jsresolve

import "errors"

var (
	errUnsupportedNPMLockLayout  = errors.New("unsupported npm lock layout")
	errUnsupportedYarnLockLayout = errors.New("unsupported Yarn lock layout")
)
