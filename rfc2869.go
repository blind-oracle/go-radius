package radius

func init() {
	builtinOnce.Do(initDictionary)
	Builtin.MustRegister("NAS-Port-Id", 87, AttributeText)
	Builtin.MustRegister("Acct-Input-Gigawords", 52, AttributeInteger)
	Builtin.MustRegister("Acct-Output-Gigawords", 53, AttributeInteger)
}
