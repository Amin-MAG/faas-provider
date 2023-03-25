package types

type FlowChild struct {
	Args     []string `json:"args"`
	Function string   `json:"function"`
}

type Flow struct {
	Args     []string             `json:"args"`
	Children map[string]FlowChild `json:"children,omitempty"`
}

type Flows struct {
	Flows map[string]Flow `json:"flows"`
}

type FlowOutput struct {
	Data     map[string]interface{} `json:"data"`
	Function string                 `json:"function"`
}

type FlowInput struct {
	Args     map[string]interface{} `json:"args"`
	Children map[string]*FlowOutput `json:"children"`
}