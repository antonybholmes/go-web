package access

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/antonybholmes/go-sys"
	"github.com/antonybholmes/go-sys/log"
	"github.com/antonybholmes/go-web/auth"
	"github.com/antonybholmes/go-web/auth/token"
	"github.com/golang-jwt/jwt/v5"
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

type (
	JsonTokenRule struct {
		Type        string   `json:"type"`
		Permissions []string `json:"permissions"`
	}

	JsonMethodRule struct {
		Type   string          `json:"type"`
		Tokens []JsonTokenRule `json:"tokens"`
	}

	// JSON structure for rules
	JsonRule struct {
		Methods  []JsonMethodRule `json:"methods"`
		Path     string           `json:"path"`
		Audience jwt.ClaimStrings `json:"audience"`
	}

	JsonRules struct {
		Version string     `json:"version"`
		Updated string     `json:"updated"`
		Rules   []JsonRule `json:"rules"`
	}

	AccessRuleError struct {
		s string
	}

	RuleEngine struct {
		//rules map[string]map[string]map[string]map[string]*sys.StringSet
		rules         map[string]*sys.Set[string]
		wildcardRules map[string]map[string]*sys.Set[string]
	}
)

func NewAccessRuleError(s string) *AccessRuleError {
	return &AccessRuleError{s: s}
}

func (e *AccessRuleError) Error() string {
	return fmt.Sprintf("access rule error: %s", e.s)
}

func makeRuleKey(method, tokenType string, audience jwt.ClaimStrings, path string) string {

	return makeWildcardRuleKey(method, tokenType, audience) + "|" + path
}

func makeWildcardRuleKey(method, tokenType string, audience jwt.ClaimStrings) string {
	if len(audience) == 0 {
		audience = jwt.ClaimStrings{"*"}
	}

	return strings.ToLower(method + "|" + tokenType + "|" + strings.Join(audience, ","))

}

func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:         make(map[string]*sys.Set[string]),
		wildcardRules: make(map[string]map[string]*sys.Set[string]),
	}
}

// LoadRules loads access control rules from a JSON file.
// This will panic if the file cannot be read or parsed since
// it is assumed that the rules file is correct and present at startup.
func (re *RuleEngine) LoadRules(filename string) {
	data := sys.Must(os.ReadFile(filename))

	var rules JsonRules
	sys.VoidMust(json.Unmarshal(data, &rules))
	var isExact bool

	for _, r := range rules.Rules {

		path := r.Path

		isExact = !strings.HasSuffix(path, "/*")

		path = strings.TrimSuffix(path, "/*")

		// remove trailing slash if present
		path = strings.TrimSuffix(path, "/")

		// rule := Rule{
		// 	Method: strings.ToUpper(r.Method),
		// 	Path:   path,
		// 	Token:  r.Token,
		// 	Roles:  sys.NewStringSet().ListUpdate(r.Roles),
		// }

		// which method types does this rule apply to e.g. GET, POST etc
		for _, m := range r.Methods {

			// which types of tokens are accepted for this rule
			for _, t := range m.Tokens {

				if isExact {
					re.rules[makeRuleKey(m.Type, t.Type, r.Audience, path)] = sys.NewStringSet().ListUpdate(t.Permissions)
				} else {
					key := makeWildcardRuleKey(m.Type, t.Type, r.Audience)

					if re.wildcardRules[key] == nil {
						re.wildcardRules[key] = make(map[string]*sys.Set[string])
					}

					re.wildcardRules[key][path] = sys.NewStringSet().ListUpdate(t.Permissions)
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
				// re.rules[matchType][methodType][tokenType][path] = sys.NewStringSet().ListUpdate(t.Permissions) //  = append(re.rules[rule.Method][rule.Token][rule.Path], rule)
			}
		}
	}

	log.Info().Msgf("Loaded %d access rules from %s", len(rules.Rules), filename)
}

func (re *RuleEngine) getWildCardRoles(method string, tokenType string, audience jwt.ClaimStrings, path string) (*sys.Set[string], error) {
	log.Debug().Msgf("GetWildCardRoles: method=%s, tokenType=%s, path=%s", method, tokenType, path)

	key := makeWildcardRuleKey(method, tokenType, audience)

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

func (re *RuleEngine) getExactRoles(method string,

	path string, token *token.AuthUserJwtClaims) (*sys.Set[string], error) {

	log.Debug().Msgf("GetExactRoles: method=%s, tokenType=%s, path=%s", method, token.Type, path)

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

	key := makeRuleKey(method, token.Type, token.Audience, path)

	//log.Debug().Msgf("Looking for exact rule with key=%s", key)
	//log.Debug().Msgf("Available exact rules: %v", strings.Join(sys.SortedMapKeys(re.rules), ", "))

	// Exact match rules, ideally all routes should be exact matches
	rules, ok := re.rules[key]

	if !ok {
		return nil, NewAccessRuleError("no rules found")
	}

	return rules, nil
}

func (re *RuleEngine) GetRoutePermissions(method string, path string, token *token.AuthUserJwtClaims) (*sys.Set[string], error) {
	method = strings.ToLower(method)

	// normalize path by removing trailing slash if present
	path = strings.TrimSuffix(path, "/")

	rules, err := re.getExactRoles(method, path, token)

	if err == nil {
		return rules, nil
	}

	// try wildcard rules

	return re.getWildCardRoles(method, token.Type, token.Audience, path)

}

func (re *RuleEngine) IsAccessAllowed(method, path string, token *token.AuthUserJwtClaims) error {

	log.Debug().Msgf("IsAccessAllowed: method=%s, path=%s, tokenType=%s, permissions=%v", method, path, token.Type, token.Permissions)

	matchingPermissions, err := re.GetRoutePermissions(method, path, token)

	if err != nil {
		return err
	}

	// route must contain at least one of the user's roles

	if auth.HasAdminPermission(token.Permissions) {
		// Admin has access to everything
		log.Debug().Msgf("access allowed for admin permissions %v", token.Permissions)
		return nil
	}

	//roleList := auth.FlattenRoles(roles)

	userPermissions := matchingPermissions.WhichList(token.Permissions)

	if len(userPermissions) > 0 {
		log.Debug().Msgf("Access allowed for permissions %v", userPermissions)
		return nil
	}

	// for _, rule := range matchingRules {
	// 	// Check if any of the user's roles match the rule's roles
	// 	if rule.Roles.Contains(roleSet) {
	// 		return nil
	// 	}
	// }

	// No rules matched the user's roles, deny access
	return NewAccessRuleError("no matching roles")
}
