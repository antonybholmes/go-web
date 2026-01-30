package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
)

// Creates the IN clause for permissions and appends named args
// for use in sql query so it can be done in a safe way
func MakePermissionsInClause(permissions []string, namedArgs *[]any) string {
	inPlaceholders := make([]string, len(permissions))

	for i, perm := range permissions {
		ph := fmt.Sprintf("perm%d", i+1)
		inPlaceholders[i] = ":" + ph
		*namedArgs = append(*namedArgs, sql.Named(ph, perm))
	}

	return strings.Join(inPlaceholders, ",")
}
