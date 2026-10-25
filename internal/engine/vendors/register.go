package vendors

import "vecmap/internal/engine"

// RegisterAll 将全部内置厂商适配器注册到注册表。
//
// 参数 registry 为适配器注册表，runtime 为共享协议客户端。
// 返回注册错误；任一台适配器重复注册或无效时返回错误。
func RegisterAll(registry *engine.Registry, runtime *engine.Runtime) error {
	adapters := []engine.Adapter{
		NewQdrant(runtime),
		NewMilvus(runtime),
		NewWeaviate(runtime),
		NewChroma(runtime),
		NewRedis(runtime),
		NewElasticsearch(runtime),
		NewOpenSearch(runtime),
		NewPgVector(runtime),
		NewTypesense(runtime),
		NewPinecone(runtime),
		NewVespa(runtime),
	}
	for _, adapter := range adapters {
		if err := registry.Register(adapter); err != nil {
			return err
		}
	}
	return nil
}
