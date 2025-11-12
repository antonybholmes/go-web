package access

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-web/auth"
	"github.com/rs/zerolog/log"
)

// func matchesWildcardRule(rulePath, actualPath string) bool {
// 	if strings.HasSuffix(rulePath, "/*") {
// 		prefix := strings.TrimSuffix(rulePath, "/*")
// 		return strings.HasPrefix(actualPath, prefix)
// 	}
// 	return rulePath == actualPath
// }

// const (
// 	MATCH_TYPE_EXACT    = "exact"
// 	MATCH_TYPE_WILDCARD = "wildcard"
// )

type JsonTokenRule struct {
	Type  string   `json:"type"`
	Roles []string `json:"roles"`
}

type JsonMethodRule struct {
	Type   string          `json:"type"`
	Tokens []JsonTokenRule `json:"tokens"`
}

// JSON structure for rules
type JsonRule struct {
	Methods []JsonMethodRule `json:"methods"`
	Path    string           `json:"path"`
}

type JsonRules struct {
	Version string     `json:"version"`
	Updated string     `json:"updated"`
	Rules   []JsonRule `json:"rules"`
}

// type TokenRule struct {
// 	Type  string         `json:"type"`
// 	Roles *sys.StringSet `json:"roles"`
// }

// Rule represents an access control rule
// type Rule struct {
// 	Method string         `json:"method"`
// 	Path   string         `json:"path"`
// 	Token  string         `json:"token"`
// 	Roles  *sys.StringSet `json:"roles"`
// }

func makeRuleKey(method, tokenType, path string) string {
	return strings.ToLower(strings.Join([]string{method, tokenType, path}, "|"))
}

func makeWildcardRuleKey(method, tokenType string) string {
	return strings.ToLower(strings.Join([]string{method, tokenType}, "|"))
}

type RuleEngine struct {
	//rules map[string]map[string]map[string]map[string]*sys.StringSet
	rules         map[string]*sys.StringSet
	wildcardRules map[string]map[string]*sys.StringSet
}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:         make(map[string]*sys.StringSet),
		wildcardRules: make(map[string]map[string]*sys.StringSet),
	}
}

// LoadRules loads access control rules from a JSON file.
// This will panic if the file cannot be read or parsed since
// it is assumed that the rules file is correct and present at startup.
func (re *RuleEngine) LoadRules(filename string) {
	data := sys.Must(os.ReadFile(filename))

	var rules JsonRules
	sys.BaseMust(json.Unmarshal(data, &rules))
	var isExact bool

	for _, r := range rules.Rules {

		path := r.Path

		isExact = !strings.HasSuffix(path, "/*")

		if strings.HasSuffix(path, "/*") {

			prefix := strings.TrimSuffix(path, "/*")

			// Adjust the rule path to be the prefix without the wildcard
			path = prefix
		}

		// remove trailing slash if present
		path = strings.TrimSuffix(path, "/")

		// rule := Rule{
		// 	Method: strings.ToUpper(r.Method),
		// 	Path:   path,
		// 	Token:  r.Token,
		// 	Roles:  sys.NewStringSet().ListUpdate(r.Roles),
		// }

		for _, m := range r.Methods {

			methodType := strings.ToLower(m.Type)

			for _, t := range m.Tokens {

				tokenType := strings.ToLower(t.Type)

				if isExact {
					re.rules[makeRuleKey(methodType, tokenType, path)] = sys.NewStringSet().ListUpdate(t.Roles)
				} else {
					key := makeWildcardRuleKey(methodType, tokenType)
					if re.wildcardRules[key] == nil {
						re.wildcardRules[key] = make(map[string]*sys.StringSet)
					}
					re.wildcardRules[key][path] = sys.NewStringSet().ListUpdate(t.Roles)
				}

				// if re.rules[matchType] == nil {
				// 	re.rules[matchType] = make(map[string]map[string]map[string]*sys.StringSet)
				// }

				// if re.rules[matchType][methodType] == nil {
				// 	re.rules[matchType][methodType] = make(map[string]map[string]*sys.StringSet)
				// }

				// if re.rules[matchType][methodType][tokenType] == nil {
				// 	re.rules[matchType][methodType][tokenType] = make(map[string]*sys.StringSet)
				// }

				// // path is last as this is the most expensive to check
				// // so we can quickly eliminate rules that don't match method or token
				// // before checking path
				// re.rules[matchType][methodType][tokenType][path] = sys.NewStringSet().ListUpdate(t.Roles) //  = append(re.rules[rule.Method][rule.Token][rule.Path], rule)
			}
		}
	}

	log.Info().Msgf("Loaded %d access rules from %s", len(rules.Rules), filename)
}

func (re *RuleEngine) getWildCardRoles(method string, tokenType string, path string) (*sys.StringSet, error) {
	log.Debug().Msgf("GetWildCardRoles: method=%s, tokenType=%s, path=%s", method, tokenType, path)

	key := makeWildcardRuleKey(method, tokenType)

	// matchTypeRules, ok := re.rules[MATCH_TYPE_WILDCARD]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for match type %s for path %s", MATCH_TYPE_EXACT, path)
	// }

	// methodRules, ok := matchTypeRules[method]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for method %s for path %s", method, path)
	// }

	tokenRules, ok := re.wildcardRules[key]

	if !ok {
		return nil, fmt.Errorf("no rules for token type %s for method %s for path %s", tokenType, method, path)
	}

	// sort paths descending by length so that the longest match is found first
	rulePaths := make([]string, 0, len(tokenRules))

	for rulePath := range tokenRules {
		rulePaths = append(rulePaths, rulePath)
	}

	sort.Slice(rulePaths, func(i, j int) bool {
		return len(rulePaths[i]) > len(rulePaths[j])
	})

	// find the first matching rule that is longest
	for _, rulePath := range rulePaths {

		// see if path starts with rulePath prefix
		if strings.HasPrefix(path, rulePath) {
			return tokenRules[rulePath], nil
		}

	}

	// No matching rules found
	return nil, fmt.Errorf("no rules found")
}

func (re *RuleEngine) getExactRoles(method string, tokenType string, path string) (*sys.StringSet, error) {
	log.Debug().Msgf("GetExactRoles: method=%s, tokenType=%s, path=%s", method, tokenType, path)

	// matchTypeRules, ok := re.rules[MATCH_TYPE_EXACT]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for match type %s for path %s", MATCH_TYPE_EXACT, path)
	// }

	// methodRules, ok := matchTypeRules[method]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for method %s for path %s", method, path)
	// }

	// tokenRules, ok := methodRules[tokenType]

	// if !ok {
	// 	return nil, fmt.Errorf("no rules for token type %s for method %s for path %s", tokenType, method, path)
	// }

	key := makeRuleKey(method, tokenType, path)

	// Exact match rules, ideally all routes should be exact matches
	rules, ok := re.rules[key]

	if !ok {
		return nil, fmt.Errorf("no rules found")
	}

	return rules, nil
}

func (re *RuleEngine) GetMatchingRoles(method string, tokenType string, path string) (*sys.StringSet, error) {
	method = strings.ToLower(method)
	tokenType = strings.ToLower(tokenType)
	// normalize path by removing trailing slash if present
	path = strings.TrimSuffix(path, "/")

	rules, err := re.getExactRoles(method, tokenType, path)

	if err == nil {
		return rules, nil
	}

	// try wildcard rules

	return re.getWildCardRoles(method, tokenType, path)

}

func (re *RuleEngine) IsAccessAllowed(method, path string, tokenType string, roles []*auth.RolePermissions) error {

	log.Debug().Msgf("IsAccessAllowed: method=%s, path=%s, tokenType=%s, roles=%v", method, path, tokenType, roles)

	matchingRoles, err := re.GetMatchingRoles(method, tokenType, path)

	if err != nil {
		return err
	}

	// route must contain at least one of the user's roles

	if auth.HasAdminRole(roles) {
		// Admin has access to everything
		log.Debug().Msgf("Access allowed for admin roles %v", roles)
		return nil
	}

	roleList := auth.FlattenRoles(roles)

	userRoles := matchingRoles.WhichList(roleList)

	if len(userRoles) > 0 {
		log.Debug().Msgf("Access allowed for roles %v", userRoles)
		return nil
	}

	// for _, rule := range matchingRules {
	// 	// Check if any of the user's roles match the rule's roles
	// 	if rule.Roles.Contains(roleSet) {
	// 		return nil
	// 	}
	// }

	// No rules matched the user's roles, deny access
	return fmt.Errorf("no matching roles")
}
