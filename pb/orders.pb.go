// Code generated by protoc-gen-go. DO NOT EDIT.
// source: orders.proto

package pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type OrderState int32

const (
	// Order has been funded and sent to the vendor but vendor has not yet responded
	OrderState_PENDING OrderState = 0
	// Waiting for the buyer to fund the payment address
	OrderState_AWAITING_PAYMENT OrderState = 1
	// Waiting for the customer to pick up the order (customer pickup option only)
	OrderState_AWAITING_PICKUP OrderState = 2
	// Order has been fully funded and we're waiting for the vendor to fulfill
	OrderState_AWAITING_FULFILLMENT OrderState = 3
	// Vendor has fulfilled part of the order
	OrderState_PARTIALLY_FULFILLED OrderState = 4
	// Vendor has fulfilled the order
	OrderState_FULFILLED OrderState = 5
	// Buyer has completed the order and left a review
	OrderState_COMPLETED OrderState = 6
	// Buyer canceled the order (offline order only)
	OrderState_CANCELED OrderState = 7
	// Vendor declined to confirm the order (offline order only)
	OrderState_DECLINED OrderState = 8
	// Vendor refunded the order
	OrderState_REFUNDED OrderState = 9
	// Contract is under active dispute
	OrderState_DISPUTED OrderState = 10
	// The moderator has resolved the dispute and we are waiting for the winning party to
	// accept the payout.
	OrderState_DECIDED OrderState = 11
	// The winning party has accepted the dispute and it is now complete. After the buyer
	// leaves a review the state should be set to COMPLETE.
	OrderState_RESOLVED OrderState = 12
	// Escrow has been released after waiting the timeout period. After the buyer
	// leaves a review the state should be set to COMPLETE.
	OrderState_PAYMENT_FINALIZED OrderState = 13
)

var OrderState_name = map[int32]string{
	0:  "PENDING",
	1:  "AWAITING_PAYMENT",
	2:  "AWAITING_PICKUP",
	3:  "AWAITING_FULFILLMENT",
	4:  "PARTIALLY_FULFILLED",
	5:  "FULFILLED",
	6:  "COMPLETED",
	7:  "CANCELED",
	8:  "DECLINED",
	9:  "REFUNDED",
	10: "DISPUTED",
	11: "DECIDED",
	12: "RESOLVED",
	13: "PAYMENT_FINALIZED",
}
var OrderState_value = map[string]int32{
	"PENDING":              0,
	"AWAITING_PAYMENT":     1,
	"AWAITING_PICKUP":      2,
	"AWAITING_FULFILLMENT": 3,
	"PARTIALLY_FULFILLED":  4,
	"FULFILLED":            5,
	"COMPLETED":            6,
	"CANCELED":             7,
	"DECLINED":             8,
	"REFUNDED":             9,
	"DISPUTED":             10,
	"DECIDED":              11,
	"RESOLVED":             12,
	"PAYMENT_FINALIZED":    13,
}

func (x OrderState) String() string {
	return proto.EnumName(OrderState_name, int32(x))
}
func (OrderState) EnumDescriptor() ([]byte, []int) { return fileDescriptor6, []int{0} }

func init() {
	proto.RegisterEnum("OrderState", OrderState_name, OrderState_value)
}

func init() { proto.RegisterFile("orders.proto", fileDescriptor6) }

var fileDescriptor6 = []byte{
	// 228 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x44, 0x90, 0xcb, 0x4e, 0xc3, 0x40,
	0x0c, 0x45, 0x69, 0x29, 0x7d, 0xb8, 0xa9, 0x30, 0xd3, 0x22, 0xf8, 0x06, 0x16, 0x6c, 0xf8, 0x82,
	0x61, 0xec, 0x54, 0x16, 0xee, 0x64, 0xd4, 0x64, 0x40, 0xed, 0xa6, 0xa2, 0xa2, 0xeb, 0x54, 0x21,
	0xff, 0x0f, 0x9a, 0xf0, 0xc8, 0xf2, 0xdc, 0x73, 0xbd, 0xb8, 0x86, 0xac, 0x6e, 0x3e, 0x4e, 0xcd,
	0xe7, 0xe3, 0xb9, 0xa9, 0xdb, 0xfa, 0xe1, 0x6b, 0x00, 0x50, 0xa4, 0xa0, 0x6c, 0xdf, 0xdb, 0x93,
	0x99, 0xc3, 0x24, 0xb0, 0x27, 0xf1, 0x6b, 0xbc, 0x30, 0x2b, 0x40, 0xfb, 0x66, 0xa5, 0x12, 0xbf,
	0x3e, 0x04, 0xbb, 0xdb, 0xb0, 0xaf, 0x70, 0x60, 0x96, 0x70, 0xdd, 0xa7, 0xe2, 0x5e, 0x62, 0xc0,
	0xa1, 0xb9, 0x87, 0xd5, 0x7f, 0x98, 0x47, 0xcd, 0x45, 0xb5, 0xab, 0x5f, 0x9a, 0x3b, 0x58, 0x06,
	0xbb, 0xad, 0xc4, 0xaa, 0xee, 0xfe, 0x14, 0x13, 0x8e, 0xcc, 0x02, 0x66, 0x3d, 0x5e, 0x25, 0x74,
	0xc5, 0x26, 0x28, 0x57, 0x4c, 0x38, 0x36, 0x19, 0x4c, 0x9d, 0xf5, 0x8e, 0x93, 0x9c, 0x24, 0x22,
	0x76, 0x2a, 0x9e, 0x09, 0xa7, 0x89, 0xb6, 0x9c, 0x47, 0x4f, 0x4c, 0x38, 0xeb, 0x9c, 0x94, 0x21,
	0xa6, 0x3b, 0x48, 0x03, 0x88, 0x9d, 0x24, 0x35, 0xff, 0x29, 0x96, 0x85, 0xbe, 0x32, 0x61, 0x66,
	0x6e, 0xe1, 0xe6, 0x77, 0xc5, 0x21, 0x17, 0x6f, 0x55, 0xf6, 0x4c, 0xb8, 0x78, 0x1e, 0xed, 0x87,
	0xe7, 0xe3, 0x71, 0xdc, 0xbd, 0xe3, 0xe9, 0x3b, 0x00, 0x00, 0xff, 0xff, 0x4e, 0x1c, 0x6d, 0xcd,
	0x1e, 0x01, 0x00, 0x00,
}
