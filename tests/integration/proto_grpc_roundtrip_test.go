//go:build integration

package integration_test

import (
	"context"
	"net"
	"testing"
	"time"

	mcpidsv1 "github.com/mcpids/mcpids/pkg/proto/gen/mcpids/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufconnSize = 1 << 20

type fakeInventoryService struct{}

func (fakeInventoryService) ReportInventory(_ context.Context, req *mcpidsv1.InventoryReport) (*mcpidsv1.InventoryAck, error) {
	ack := &mcpidsv1.InventoryAck{ServerIds: map[string]string{}}
	for _, server := range req.Servers {
		ack.ServerIds[server.Name] = "server-" + server.Name
	}
	return ack, nil
}

func (fakeInventoryService) SubmitToolSnapshot(_ context.Context, _ *mcpidsv1.ToolSnapshotRequest) (*mcpidsv1.ToolSnapshotAck, error) {
	return &mcpidsv1.ToolSnapshotAck{SnapshotId: "snapshot-1", HasChanges: true, ChangeSummary: "changed"}, nil
}

func (fakeInventoryService) GetServerTools(_ context.Context, _ *mcpidsv1.GetServerToolsRequest) (*mcpidsv1.GetServerToolsResponse, error) {
	return &mcpidsv1.GetServerToolsResponse{ToolsJson: []byte(`[{"name":"read_file"}]`), SnapshotId: "snapshot-1", SnapshotAt: time.Now().UTC().UnixMilli()}, nil
}

type fakePolicyService struct{}

func (fakePolicyService) GetPolicy(_ context.Context, req *mcpidsv1.GetPolicyRequest) (*mcpidsv1.GetPolicyResponse, error) {
	return &mcpidsv1.GetPolicyResponse{
		Snapshot: &mcpidsv1.PolicySnapshot{
			TenantId:     req.TenantId,
			Version:      1,
			PoliciesJson: []byte(`[]`),
			RulesJson:    []byte(`[]`),
		},
	}, nil
}

func (fakePolicyService) StreamPolicyUpdates(req *mcpidsv1.StreamPolicyUpdatesRequest, stream mcpidsv1.PolicyService_StreamPolicyUpdatesServer) error {
	return stream.Send(&mcpidsv1.PolicyUpdate{
		TenantId: req.TenantId,
		Sequence: 1,
		FullSnapshot: &mcpidsv1.PolicySnapshot{
			TenantId:     req.TenantId,
			Version:      1,
			PoliciesJson: []byte(`[]`),
			RulesJson:    []byte(`[]`),
		},
	})
}

func TestGeneratedProtoGRPCRoundTrip(t *testing.T) {
	lis := bufconn.Listen(bufconnSize)
	srv := grpc.NewServer()
	mcpidsv1.RegisterInventoryServiceServer(srv, fakeInventoryService{})
	mcpidsv1.RegisterPolicyServiceServer(srv, fakePolicyService{})
	go func() {
		_ = srv.Serve(lis)
	}()
	defer srv.Stop()

	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(dialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	inventoryClient := mcpidsv1.NewInventoryServiceClient(conn)
	ack, err := inventoryClient.ReportInventory(context.Background(), &mcpidsv1.InventoryReport{
		TenantId: "tenant-1",
		AgentId:  "agent-1",
		Servers: []*mcpidsv1.DiscoveredServer{{
			Name:      "local-files",
			Transport: "stdio",
		}},
	})
	if err != nil {
		t.Fatalf("ReportInventory: %v", err)
	}
	if ack.ServerIds["local-files"] != "server-local-files" {
		t.Fatalf("unexpected ack: %+v", ack.ServerIds)
	}

	policyClient := mcpidsv1.NewPolicyServiceClient(conn)
	stream, err := policyClient.StreamPolicyUpdates(context.Background(), &mcpidsv1.StreamPolicyUpdatesRequest{
		TenantId: "tenant-1",
		AgentId:  "agent-1",
	})
	if err != nil {
		t.Fatalf("StreamPolicyUpdates: %v", err)
	}
	update, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if update.Sequence != 1 || update.FullSnapshot == nil || update.FullSnapshot.TenantId != "tenant-1" {
		t.Fatalf("unexpected update: %+v", update)
	}
}
