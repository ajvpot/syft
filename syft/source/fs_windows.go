package source

// getDeviceID is unimplmented on windows.
func getDeviceID(os.FileInfo) (uint64, error) {
	return 0, nil
}