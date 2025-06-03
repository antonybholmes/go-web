package web

import (
	"fmt"
	"regexp"
	"strings"
)

var SPACES_REGEX = regexp.MustCompile(`\s+`)

// Parses a query into blocks of and tags using
// a simple query format of plus and space for AND and comma for OR
// Thus foo+bar,thing -> [['foo', 'bar'], ['thing']]
func ParseQuery(query string) (orTags []string, andTags [][]string) {
	groups := strings.Split(query, ",") // comma separates OR groups
	andTags = make([][]string, 0, len(groups))
	for _, group := range groups {
		// trim each piece and replace spaces with + since we treat spaces as being AND
		parts := strings.Split(SPACES_REGEX.ReplaceAllString(strings.TrimSpace(group), "+"), "+") // plus separates AND parts
		andTags = append(andTags, parts)
	}
	return groups, andTags
}

// Creates a boolean sql query from a text query using + for AND and comma for OR.
// User must supply a clause function that given a placeholder string, returns
// the core part of the query that matches to the placeholder item. This is done
// this way to provide flexibility when defining the query, e.g. we can check multiple
// table fields for the same placeholder if necessary
func BoolQuery(query string, clause func(placeholder string) string) (string, []interface{}) {
	_, andTags := ParseQuery(query)

	andClauses := make([]string, 0, len(andTags))

	// required so that we can use it with sqlite params
	args := make([]interface{}, 0, len(andTags))

	for _, group := range andTags {
		tagClauses := make([]string, 0, len(group))
		for _, tag := range group {
			args = append(args, "%"+tag+"%")
			placeholder := fmt.Sprintf("?%d", len(args))
			//tagClauses = append(tagClauses, fmt.Sprintf("(gex.gene_symbol LIKE %s OR gex.ensembl_id LIKE %s)", placeholder, placeholder))
			tagClauses = append(tagClauses, clause(placeholder))
		}
		andClauses = append(andClauses, "("+strings.Join(tagClauses, " AND ")+")")
	}

	finalSQL := strings.Join(andClauses, " OR ")

	return finalSQL, args
}
