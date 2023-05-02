package jws

import "strings"

// set takes an array of strings and returns a new arryay
// where each element appears exactly once
func set(array []string) []string {
	present := map[string]bool{}
	result := []string{}

	for i := 0; i < len(array); i++ {
		if !present[array[i]] {
			present[array[i]] = true
			result = append(result, array[i])
		}
	}

	return result
}

// lowerAll receives an array and changes it in place by making each element lowercase.
// Returns a pointer to the modified array.
func lowerAll(array []string) []string {
	for i := 0; i < len(array); i++ {
		array[i] = strings.ToLower(array[i])
	}

	return array
}
