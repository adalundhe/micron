package models

func StringPtr(s string) *string {
	return &s
}

func StringListPtr(s []string) *[]string {
	return &s
}

func Int64Ptr(i int64) *int64 {
	return &i
}

func BoolPtr(b bool) *bool {
	return &b
}

func Float64Ptr(f float64) *float64 {
	return &f
}

func IntPtr(i int) *int {
	return &i
}
