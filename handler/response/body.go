package response

type BodyName interface {
	BodyName() string
}

type Body map[string]interface{}

func NewResponse(data interface{}, kv ...interface{}) Body {
	result := Body{}
	if v, ok := data.(BodyName); ok {
		result[v.BodyName()] = data
	} else {
		result["data"] = data
	}
	for i := 0; i < len(kv); i += 2 {
		key := kv[i]
		value := kv[i+1]
		if v, ok := key.(string); ok {
			result[v] = value
		}
	}
	return result
}
