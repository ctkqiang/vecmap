package constant

type Vendor string
type Protocol string
type Port int

type VectorDB struct {
	Name        Vendor
	DefaultPort Port
	Protocol    Protocol
}

const (
	VendorWeaviate Vendor = "Weaviate"
	VendorQdrant   Vendor = "Qdrant"
	VendorMilvus   Vendor = "Milvus"
	VendorChroma   Vendor = "Chroma"
	VendorPgVector Vendor = "pgvector"

	ProtocolHTTP Protocol = "HTTP"
	ProtocolGRPC Protocol = "GRPC"
	ProtocolTCP  Protocol = "TCP"

	PortWeaviate   Port = 8080
	PortQdrantREST Port = 6333
	PortQdrantGRPC Port = 6334
	PortMilvus     Port = 19530
	PortChroma     Port = 8000
	PortPostgres   Port = 5432
)

var SupportedVendors = map[Vendor]VectorDB{
	VendorWeaviate: {
		Name:        VendorWeaviate,
		DefaultPort: PortWeaviate,
		Protocol:    ProtocolHTTP,
	},
	VendorQdrant: {
		Name:        VendorQdrant,
		DefaultPort: PortQdrantREST,
		Protocol:    ProtocolHTTP,
	},
	VendorMilvus: {
		Name:        VendorMilvus,
		DefaultPort: PortMilvus,
		Protocol:    ProtocolGRPC,
	},
	VendorChroma: {
		Name:        VendorChroma,
		DefaultPort: PortChroma,
		Protocol:    ProtocolHTTP,
	},
}
