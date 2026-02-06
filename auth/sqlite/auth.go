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
	//inClause := MakePermissionsInClause(permissions, isAdmin, namedArgs)

	// (:is_admin = 1 OR p.name IN (<<PERMISSIONS>>))

	// add is_admin named to shortcircuit permissions check
	if isAdmin {
		*namedArgs = append(*namedArgs, sql.Named("is_admin", isAdmin))

		// we must have a clause to check since this is combined with AND/OR
		// so just return a true clause
		return strings.Replace(query, "<<PERMISSIONS>>", ":is_admin = 1", 1)
	}

	inPlaceholders := make([]string, len(permissions))

	for i, perm := range permissions {
		ph := fmt.Sprintf("perm%d", i+1)
		inPlaceholders[i] = ":" + ph
		*namedArgs = append(*namedArgs, sql.Named(ph, perm))
	}

	clause := "p.name IN (" + strings.Join(inPlaceholders, ",") + ")"

	return strings.Replace(query, "<<PERMISSIONS>>", clause, 1)

}
