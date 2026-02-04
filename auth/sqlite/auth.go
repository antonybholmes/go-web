package sqlite

import (
	"database/sql"
	"fmt"
	"strings"
)

// Creates the IN clause for permissions and appends named args
// for use in sql query so it can be done in a safe way
func MakePermissionsInClause(permissions []string, isAdmin bool, namedArgs *[]any) string {
	*namedArgs = append(*namedArgs, sql.Named("is_admin", isAdmin))

	inPlaceholders := make([]string, len(permissions))

	for i, perm := range permissions {
		ph := fmt.Sprintf("perm%d", i+1)
		inPlaceholders[i] = ":" + ph
		*namedArgs = append(*namedArgs, sql.Named(ph, perm))
	}

	return strings.Join(inPlaceholders, ",")
}

// Replaces <<PERMISSIONS>> in query with the appropriate IN clause
// and appends named args for use in sql query so it can be done in a safe way
func MakePermissionsSql(query string, permissions []string, isAdmin bool, namedArgs *[]any) string {
	inClause := MakePermissionsInClause(permissions, isAdmin, namedArgs)

	query = strings.Replace(query, "<<PERMISSIONS>>", inClause, 1)

	return query
}
