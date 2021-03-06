package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/OpenBazaar/jsonpb"
	"github.com/OpenBazaar/openbazaar-go/core"
	"github.com/OpenBazaar/openbazaar-go/pb"
	"github.com/OpenBazaar/openbazaar-go/repo"
	"github.com/OpenBazaar/openbazaar-go/schema"
	"github.com/OpenBazaar/openbazaar-go/test"
	"github.com/OpenBazaar/openbazaar-go/test/factory"
)

func TestMain(m *testing.M) {
	// Create a test server
	gateway, err := newTestGateway()
	if err != nil {
		log.Fatal(err)
	}
	defer gateway.Close()

	go func() {
		err = gateway.Serve()
		if err != nil {
			log.Fatal(err)
		}
	}()

	// Run tests
	retCode := m.Run()

	os.Exit(retCode)
}

func TestSettings(t *testing.T) {
	// Create, Read, Update, Patch
	runAPITests(t, apiTests{
		{"POST", "/ob/settings", settingsJSON, 200, settingsJSON},
		{"GET", "/ob/settings", "", 200, settingsJSON},
		{"POST", "/ob/settings", settingsJSON, 409, settingsAlreadyExistsJSON},
		{"PUT", "/ob/settings", settingsUpdateJSON, 200, "{}"},
		{"GET", "/ob/settings", "", 200, settingsUpdateJSON},
		{"PUT", "/ob/settings", settingsUpdateJSON, 200, "{}"},
		{"GET", "/ob/settings", "", 200, settingsUpdateJSON},
		{"PATCH", "/ob/settings", settingsPatchJSON, 200, "{}"},
		{"GET", "/ob/settings", "", 200, settingsPatchedJSON},
	})

	// Invalid JSON
	runAPITests(t, apiTests{
		{"POST", "/ob/settings", settingsMalformedJSON, 400, settingsMalformedJSONResponse},
	})

	// Invalid JSON
	runAPITests(t, apiTests{
		{"POST", "/ob/settings", settingsJSON, 200, settingsJSON},
		{"GET", "/ob/settings", "", 200, settingsJSON},
		{"PUT", "/ob/settings", settingsMalformedJSON, 400, settingsMalformedJSONResponse},
	})
}

func TestSettingsSetModerator(t *testing.T) {
	var (
		validSettings      = factory.MustNewValidSettings()
		jsonSettings, sErr = json.Marshal(validSettings)
		moderatorUpdate    = `{"storeModerators": ["QmeRfQcEiefLYgEFRsNqn1WjjrLjrJVAddt85htU1Up32y"]}`
	)
	if sErr != nil {
		t.Fatal(sErr)
	}

	expected := `{
	"blockedNodes": [],
	"country": "United State of Shipping",
	"localCurrency": "USD",
	"mispaymentBuffer": 1,
	"paymentDataInQR": true,
	"refundPolicy": "Refund policy.",
	"shippingAddresses": [
			{
					"addressLineOne": "123 Address Street",
					"addressLineTwo": "Suite H",
					"addressNotes": "This is a fake yet valid address for testing.",
					"city": "Shipping City",
					"company": "Shipping Company",
					"country": "United States of Shipping",
					"name": "Shipping Name",
					"postalCode": "12345-6789",
					"state": "Shipping State"
			}
	],
	"showNotifications": true,
	"showNsfw": true,
	"smtpSettings": {
			"notifications": false,
			"password": "",
			"recipientEmail": "",
			"senderEmail": "",
			"serverAddress": "",
			"username": ""
	},
	"storeModerators": [
			"QmeRfQcEiefLYgEFRsNqn1WjjrLjrJVAddt85htU1Up32y"
	],
	"termsAndConditions": "Terms and Conditions",
	"version": ""
}`
	runAPITests(t, apiTests{
		{"POST", "/ob/settings", string(jsonSettings), 200, string(jsonSettings)},
		{"PATCH", "/ob/settings", moderatorUpdate, 200, "{}"},
		{"GET", "/ob/settings", "", 200, expected},
	})
}

func TestProfile(t *testing.T) {
	// Create, Update
	runAPITests(t, apiTests{
		{"POST", "/ob/profile", profileJSON, 200, anyResponseJSON},
		{"POST", "/ob/profile", profileJSON, 409, AlreadyExistsUsePUTJSON("Profile")},
		{"PUT", "/ob/profile", profileUpdateJSON, 200, anyResponseJSON},
		{"PUT", "/ob/profile", profileUpdatedJSON, 200, anyResponseJSON},
	})
}

func TestProfileSwitchesFromPercentToFixedWithLegacySchema(t *testing.T) {
	var (
		postProfile = `{
	"handle": "test",
	"name": "Test User",
	"location": "Internet",
	"about": "The test fixture",
	"shortDescription": "Fixture",
	"contactInfo": {
		"website": "internet.com",
		"email": "email@address.com",
		"phoneNumber": "687-5309"
	},
	"nsfw": false,
	"vendor": false,
	"moderator": true,
	"moderatorInfo": {
		"description": "Percentage. Test moderator account. DO NOT USE.",
		"fee": {
			"feeType": "PERCENTAGE",
			"percentage": 12.0
		}
	},
	"colors": {
		"primary": "#000000",
		"secondary": "#FFD700",
		"text": "#ffffff",
		"highlight": "#123ABC",
		"highlightText": "#DEAD00"
	},
	"currencies": ["LTC"]
}`
		patchProfile = `{
	"moderatorInfo": {
		"fee": {
			"feeType": "FIXED",
			"fixedFee": {
				"bigAmount": "1234",
				"amountCurrency": {
					"code": "USD",
					"divisibility": 2
				}
			}
		}
	}
}`
		validateProfileFees = func(testRepo *test.Repository) error {
			m, err := schema.NewCustomSchemaManager(schema.SchemaContext{
				DataPath:        testRepo.Path,
				TestModeEnabled: true,
			})
			if err != nil {
				return fmt.Errorf("schema setup: %s", err.Error())
			}
			profileBytes, err := ioutil.ReadFile(m.DataPathJoin("root", "profile.json"))
			if err != nil {
				return fmt.Errorf("get profile: %s", err.Error())
			}

			var actualProfile pb.Profile
			if err := jsonpb.UnmarshalString(string(profileBytes), &actualProfile); err != nil {
				return fmt.Errorf("unmarshal profile: %s", err.Error())
			}

			fees := actualProfile.ModeratorInfo.Fee
			if ft := fees.GetFeeType().String(); ft != pb.Moderator_Fee_FIXED.String() {
				return fmt.Errorf("expected patched profile fee type to be (%s), but was (%s)", pb.Moderator_Fee_FIXED.String(), ft)
			}

			fixedFee := fees.GetFixedFee()
			if amt := fixedFee.GetBigAmount(); amt != "1234" {
				return fmt.Errorf("expected patched profile fixed fee big amount to be (1234), but was (%s)", amt)
			}
			if amt := fixedFee.GetAmount(); amt != 1234 { //nolint:staticcheck
				return fmt.Errorf("expected patched profile fixed fee amount to be (1234), but was (%d)", amt)
			}
			if cc := fixedFee.GetAmountCurrency().GetCode(); cc != "USD" {
				return fmt.Errorf("expected patched profile fixed fee currency to be (USD), but was (%s)", cc)
			}
			if cc := fixedFee.GetCurrencyCode(); cc != "USD" { //nolint:staticcheck
				return fmt.Errorf("expected patched profile fixed fee currency code to be (USD), but was (%s)", cc)
			}

			return nil
		}
	)

	runAPITestsWithSetup(t, apiTests{
		{"POST", "/ob/profile", postProfile, 200, anyResponseJSON},
		{"PATCH", "/ob/profile", patchProfile, 200, "{}"},
	}, nil, validateProfileFees)
}

func TestPatchProfileCurrencyUpdate(t *testing.T) {
	var (
		postProfile = `{
	"handle": "test",
	"name": "Test User",
	"location": "Internet",
	"about": "The test fixture",
	"shortDescription": "Fixture",
	"contactInfo": {
		"website": "internet.com",
		"email": "email@address.com",
		"phoneNumber": "687-5309"
	},
	"nsfw": false,
	"vendor": false,
	"moderator": false,
	"colors": {
		"primary": "#000000",
		"secondary": "#FFD700",
		"text": "#ffffff",
		"highlight": "#123ABC",
		"highlightText": "#DEAD00"
	},
	"currencies": ["LTC"]
}`
		patchProfile    = `{"currencies": ["ETH"]}`
		validateProfile = func(testRepo *test.Repository) error {
			m, err := schema.NewCustomSchemaManager(schema.SchemaContext{
				DataPath:        testRepo.Path,
				TestModeEnabled: true,
			})
			if err != nil {
				return fmt.Errorf("schema setup: %s", err.Error())
			}
			profileBytes, err := ioutil.ReadFile(m.DataPathJoin("root", "profile.json"))
			if err != nil {
				return fmt.Errorf("get profile: %s", err.Error())
			}

			var actualProfile struct {
				Currencies []string `json:"currencies"`
			}
			if err := json.Unmarshal(profileBytes, &actualProfile); err != nil {
				return fmt.Errorf("unmarshal profile: %s", err.Error())
			}

			if actualProfile.Currencies[0] != "ETH" {
				t.Errorf("expected profile currency to be PATCHed but was not")
				t.Logf("expected 'ETH', found '%s'", actualProfile.Currencies[0])
			}

			if len(actualProfile.Currencies) != 1 {
				t.Errorf("expected profile currency to have 1 currency, but had %d instead", len(actualProfile.Currencies))
			}
			return nil
		}
	)

	runAPITestsWithSetup(t, apiTests{
		{"POST", "/ob/profile", postProfile, 200, anyResponseJSON},
		{"PATCH", "/ob/profile", patchProfile, 200, "{}"},
	}, nil, validateProfile)
}

func TestPatchProfileCanBeInvalid(t *testing.T) {
	var (
		// init profile for patch
		postProfile = `{
	"handle": "test",
	"name": "Test User",
	"location": "Internet",
	"about": "The test fixture",
	"shortDescription": "Fixture",
	"contactInfo": {
		"website": "internet.com",
		"email": "email@address.com",
		"phoneNumber": "687-5309"
	},
	"nsfw": false,
	"vendor": false,
	"moderator": false,
	"colors": {
		"primary": "#000000",
		"secondary": "#FFD700",
		"text": "#ffffff",
		"highlight": "#123ABC",
		"highlightText": "#DEAD00"
	},
	"currencies": ["LTC"]
}`
		// test valid patch
		patchProfile = `{
	"moderator": true,
	"moderatorInfo": {
		"description": "Fix plus percentage. Test moderator account. DO NOT USE.",
		"fee": {
			"feeType": "FIXED_PLUS_PERCENTAGE",
			"fixedFee": {
				"amountCurrency": {
					"code": "USD",
					"divisibility": 2
				},
				"bigAmount": "2"
			},
			"percentage": 0.1
		},
		"languages": [
			"en-US"
		],
		"termsAndConditions": "Test moderator account. DO NOT USE."
	}
}`
		// test invalid patch: percentage must be greater than 0
		invalidPatchProfile = `{
	"moderatorInfo": {
		"fee": {
			"percentage": -1
		}
	}
}`
	)

	expectedErr := fmt.Errorf("invalid profile: %s", repo.ErrModeratorFeeHasNegativePercentage)
	runAPITests(t, apiTests{
		{"POST", "/ob/profile", postProfile, 200, anyResponseJSON},
		{"PATCH", "/ob/profile", patchProfile, 200, "{}"},
		{"PATCH", "/ob/profile", invalidPatchProfile, 500, errorResponseJSON(expectedErr)},
	})
}

func TestProfileSwitchesFromFixedToPercent(t *testing.T) {
	var (
		postProfile = `{
	"handle": "test",
	"name": "Test User",
	"location": "Internet",
	"about": "The test fixture",
	"shortDescription": "Fixture",
	"contactInfo": {
		"website": "internet.com",
		"email": "email@address.com",
		"phoneNumber": "687-5309"
	},
	"nsfw": false,
	"vendor": false,
	"moderator": true,
	"moderatorInfo": {
		"description": "Fix plus percentage. Test moderator account. DO NOT USE.",
		"fee": {
			"feeType": "FIXED_PLUS_PERCENTAGE",
			"fixedFee": {
				"amountCurrency": {
					"code": "USD",
					"divisibility": 2
				},
				"bigAmount": "2"
			},
			"percentage": 0.1
		},
		"languages": [
			"en-US"
		],
		"termsAndConditions": "Test moderator account. DO NOT USE."
	},
	"colors": {
		"primary": "#000000",
		"secondary": "#FFD700",
		"text": "#ffffff",
		"highlight": "#123ABC",
		"highlightText": "#DEAD00"
	},
	"currencies": ["LTC"]
}`
		patchProfile = `{
	"moderatorInfo": {
		"fee": {
			"feeType": "PERCENTAGE",
			"percentage": 0.1
		}
	}
}`
		validateProfileFees = func(testRepo *test.Repository) error {
			m, err := schema.NewCustomSchemaManager(schema.SchemaContext{
				DataPath:        testRepo.Path,
				TestModeEnabled: true,
			})
			if err != nil {
				return fmt.Errorf("schema setup: %s", err.Error())
			}
			profileBytes, err := ioutil.ReadFile(m.DataPathJoin("root", "profile.json"))
			if err != nil {
				return fmt.Errorf("get profile: %s", err.Error())
			}

			var actualProfile pb.Profile
			if err := jsonpb.UnmarshalString(string(profileBytes), &actualProfile); err != nil {
				return fmt.Errorf("unmarshal profile: %s", err.Error())
			}

			fees := actualProfile.ModeratorInfo.Fee
			if ft := fees.GetFeeType().String(); ft != pb.Moderator_Fee_PERCENTAGE.String() {
				return fmt.Errorf("expected patched profile fee type to be (%s), but was (%s)", pb.Moderator_Fee_PERCENTAGE.String(), ft)
			}

			if p := fees.GetPercentage(); p != 0.1 {
				return fmt.Errorf("expected patched profile fee percentage to be (0.1), but was (%f)", p)
			}

			return nil
		}
	)
	runAPITestsWithSetup(t, apiTests{
		{"POST", "/ob/profile", postProfile, 200, anyResponseJSON},
		{"PATCH", "/ob/profile", patchProfile, 200, "{}"},
	}, nil, validateProfileFees)
}

func TestAvatar(t *testing.T) {
	// Setting an avatar fails if we don't have a profile
	runAPITests(t, apiTests{
		{"POST", "/ob/avatar", avatarValidJSON, 500, anyResponseJSON},
	})

	// It succeeds if we have a profile and the image data is valid
	runAPITests(t, apiTests{
		{"POST", "/ob/profile", profileJSON, 200, anyResponseJSON},
		{"POST", "/ob/avatar", avatarValidJSON, 200, avatarValidJSONResponse},
	})

	// Test invalid image data
	runAPITests(t, apiTests{
		{"POST", "/ob/profile", profileJSON, 200, anyResponseJSON},
		{"POST", "/ob/avatar", avatarUnexpectedEOFJSON, 500, avatarUnexpectedEOFJSONResponse},
	})

	runAPITests(t, apiTests{
		{"POST", "/ob/profile", profileJSON, 200, anyResponseJSON},
		{"POST", "/ob/avatar", avatarInvalidTQJSON, 500, avatarInvalidTQJSONResponse},
	})
}

func TestImages(t *testing.T) {
	// Valid image
	runAPITests(t, apiTests{
		{"POST", "/ob/images", imageValidJSON, 200, imageValidJSONResponse},
	})
}

func TestHeader(t *testing.T) {
	// Setting an header fails if we don't have a profile
	runAPITests(t, apiTests{
		{"POST", "/ob/header", headerValidJSON, 500, anyResponseJSON},
	})

	// It succeeds if we have a profile and the image data is valid
	runAPITests(t, apiTests{
		{"POST", "/ob/profile", profileJSON, 200, anyResponseJSON},
		{"POST", "/ob/header", headerValidJSON, 200, headerValidJSONResponse},
	})
}

func TestModerator(t *testing.T) {
	// Fails without profile
	runAPITests(t, apiTests{
		{"PUT", "/ob/moderator", moderatorValidJSON, http.StatusConflict, anyResponseJSON},
	})

	// Works with profile
	runAPITests(t, apiTests{
		{"POST", "/ob/profile", profileJSON, 200, anyResponseJSON},

		// TODO: Enable after fixing bug that requires peers in order to set moderator status
		// {"PUT", "/ob/moderator", moderatorValidJSON, 200, `{}`},

		// // Update
		// {"PUT", "/ob/moderator", moderatorUpdatedValidJSON, 200, `{}`},
		{"DELETE", "/ob/moderator", "", 200, `{}`},
	})
}

func TestMessageSignVerify(t *testing.T) {
	const (
		signMessageJSON = `{
	"content": "test"
}`
		verifyMessageJSON = `{
	"content": "test",
	"signature": "fac9dec1ce872c931bda1af85f9107e8733b42ed6401bc989a84b6b53ad263290d9bd9d470f046024884f502ecb7af50de2fea11268e82dcb1c72d50753c330a",
	"pubkey": "080112203f94c7707af68ede9ddd24a16edd813146550df565eda8fb81114476ccfe6b78",
	"peerId": "QmRmisSghsxUMrTQZ5vmqFroxxuCXJqXwXoTc21q5cefmM"
}`
	)

	runAPITests(t, apiTests{
		{"POST", "/ob/signmessage", signMessageJSON, 200, anyResponseJSON},
		{"POST", "/ob/verifymessage", verifyMessageJSON, 200, anyResponseJSON},
	})
}

func TestMessageSignsURLChars(t *testing.T) {
	const (
		validateSignWorksWithURLChars = `{
		"content":"QmdQBWA75xQSMZpTibQ2G83enNdriz2v14tetGvNrpr5KB/this-is-a-social-post"
	}`
	)

	runAPITests(t, apiTests{
		{"POST", "/ob/signmessage", validateSignWorksWithURLChars, 200, anyResponseJSON},
	})
}

func TestListingsAcceptedCurrencies(t *testing.T) {
	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, factory.NewListing("ron-swanson-tshirt")), 200, anyResponseJSON},
	})

	req, err := buildRequest("GET", "/ob/listings", "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure correct status code
	if resp.StatusCode != 200 {
		t.Fatalf("Wanted status 200, got %d", resp.StatusCode)
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	var respObj []struct {
		AcceptedCurrencies []string `json:"acceptedCurrencies"`
	}
	err = json.Unmarshal(respBody, &respObj)
	if err != nil {
		t.Fatal(err)
	}

	if len(respObj) != 1 {
		t.Fatal("Listings should contain exactly 1 listing")
	}

	if respObj[0].AcceptedCurrencies == nil {
		t.Fatal("Listing should contain exactly 1 acceptedCurrency")
	}

	if respObj[0].AcceptedCurrencies[0] != "TBTC" {
		t.Fatal("Listing acceptedCurrencies should contain 'TBTC'")
	}
}

func TestListingAcceptedCurrencies(t *testing.T) {
	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, factory.NewListing("ron-swanson-tshirt")), 200, anyResponseJSON},
	})

	req, err := buildRequest("GET", "/ob/listing/ron-swanson-tshirt", "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := testHTTPClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	// Ensure correct status code
	if resp.StatusCode != 200 {
		t.Fatalf("Wanted status 200, got %d", resp.StatusCode)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	respObj := struct {
		Listing struct {
			Metadata struct {
				AcceptedCurrencies []string `json:"acceptedCurrencies"`
			} `json:"metadata"`
		} `json:"listing"`
	}{}
	err = json.Unmarshal(respBody, &respObj)
	if err != nil {
		t.Fatal(err)
	}

	if len(respObj.Listing.Metadata.AcceptedCurrencies) != 1 {
		t.Fatal("Listing should contain exactly 1 acceptedCurrency")
	}

	if respObj.Listing.Metadata.AcceptedCurrencies[0] != "TBTC" {
		t.Fatal("Listing acceptedCurrenc9es should contain 'TBTC'")
	}
}

func TestListings(t *testing.T) {
	goodListingJSON := jsonFor(t, factory.NewListing("ron-swanson-tshirt"))
	updatedListing := factory.NewListing("ron-swanson-tshirt")
	updatedListing.Taxes = []*pb.Listing_Tax{
		{
			Percentage:  17,
			TaxShipping: true,
			TaxType:     "Sales tax",
			TaxRegions:  []pb.CountryCode{pb.CountryCode_UNITED_STATES},
		},
	}
	updatedListingJSON := jsonFor(t, updatedListing)

	runAPITests(t, apiTests{
		{"GET", "/ob/listings", "", 200, `[]`},
		{"GET", "/ob/inventory", "", 200, `{}`},

		// Invalid creates
		{"POST", "/ob/listing", `{`, 500, jsonUnexpectedEOF},

		{"GET", "/ob/listings", "", 200, `[]`},
		{"GET", "/ob/inventory", "", 200, `{}`},

		// TODO: Add support for improved JSON matching to since contracts
		// change each test run due to signatures

		// Create/Get
		{"GET", "/ob/listing/ron-swanson-tshirt", "", 404, NotFoundJSON("Listing")},
		{"POST", "/ob/listing", goodListingJSON, 200, `{"slug": "ron-swanson-tshirt"}`},
		{"GET", "/ob/listing/ron-swanson-tshirt", "", 200, anyResponseJSON},
		{"POST", "/ob/listing", updatedListingJSON, 409, AlreadyExistsUsePUTJSON("Listing")},

		// TODO: Add support for improved JSON matching to since contracts
		// change each test run due to signatures
		{"GET", "/ob/listings", "", 200, anyResponseJSON},

		// TODO: This returns `inventoryJSONResponse` but slices are unordered
		// so they don't get considered equal. Figure out a way to fix that.
		{"GET", "/ob/inventory", "", 200, anyResponseJSON},

		// Update inventory
		{"POST", "/ob/inventory", inventoryUpdateJSON, 200, `{}`},

		// Update/Get Listing
		{"PUT", "/ob/listing", updatedListingJSON, 200, `{}`},
		{"GET", "/ob/listing/ron-swanson-tshirt", "", 200, anyResponseJSON},

		// Delete/Get
		{"DELETE", "/ob/listing/ron-swanson-tshirt", "", 200, `{}`},
		{"DELETE", "/ob/listing/ron-swanson-tshirt", "", 404, NotFoundJSON("Listing")},
		{"GET", "/ob/listing/ron-swanson-tshirt", "", 404, NotFoundJSON("Listing")},

		// Mutate non-existing listings
		{"PUT", "/ob/listing", updatedListingJSON, 404, NotFoundJSON("Listing")},
		{"DELETE", "/ob/listing/ron-swanson-tshirt", "", 404, NotFoundJSON("Listing")},

		// Bulk update currency in listings
		{"POST", "/ob/bulkupdatecurrency", bulkUpdateCurrencyJSON, 200, `{"success": "true"}`},
	})
}

func TestCryptoListings(t *testing.T) {
	listing := factory.NewCryptoListing("crypto")
	updatedListing := *listing

	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, listing), 200, `{"slug": "crypto"}`},
		{"GET", "/ob/listing/crypto", jsonFor(t, &updatedListing), 200, anyResponseJSON},

		{"PUT", "/ob/listing", jsonFor(t, &updatedListing), 200, "{}"},
		{"PUT", "/ob/listing", jsonFor(t, &updatedListing), 200, "{}"},
		{"GET", "/ob/listing/crypto", jsonFor(t, &updatedListing), 200, anyResponseJSON},

		{"DELETE", "/ob/listing/crypto", "", 200, `{}`},
		{"DELETE", "/ob/listing/crypto", "", 404, NotFoundJSON("Listing")},
		{"GET", "/ob/listing/crypto", "", 404, NotFoundJSON("Listing")},
	})
}

func TestCryptoListingsPriceModifier(t *testing.T) {
	outOfRangeErr := repo.ErrPriceModifierOutOfRange{
		Min: repo.PriceModifierMin,
		Max: repo.PriceModifierMax,
	}

	listing := factory.NewCryptoListing("crypto")
	listing.Item.PriceModifier = repo.PriceModifierMax
	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, listing), 200, `{"slug": "crypto"}`},
		{"GET", "/ob/listing/crypto", jsonFor(t, listing), 200, anyResponseJSON},
	})

	listing.Item.PriceModifier = repo.PriceModifierMax + 0.001
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 200, `{"slug": "crypto"}`,
	})

	listing.Item.PriceModifier = repo.PriceModifierMax + 0.01
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(fmt.Errorf("validate sellable listing (crypto): %s", outOfRangeErr)),
	})

	listing.Item.PriceModifier = repo.PriceModifierMin - 0.001
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 200, `{"slug": "crypto"}`,
	})

	listing.Item.PriceModifier = repo.PriceModifierMin - 1
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(fmt.Errorf("validate sellable listing (crypto): %s", outOfRangeErr)),
	})
}

func TestListingsQuantity(t *testing.T) {
	listing := factory.NewListing("crypto")
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 200, `{"slug": "crypto"}`,
	})

	listing.Item.Skus[0].BigQuantity = "0"
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 200, anyResponseJSON,
	})

	listing.Item.Skus[0].BigQuantity = "-1"
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 200, anyResponseJSON,
	})
}

func TestCryptoListingsQuantity(t *testing.T) {
	listing := factory.NewCryptoListing("crypto")
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 200, `{"slug": "crypto"}`,
	})

	listing.Item.Skus[0].BigQuantity = "-1"
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(repo.ErrCryptocurrencySkuQuantityInvalid),
	})

	listing.Item.Skus[0].BigQuantity = "-1"
	runAPITest(t, apiTest{
		"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(repo.ErrCryptocurrencySkuQuantityInvalid),
	})
}

/*
func TestCryptoListingsNoCoinType(t *testing.T) {
	listing := factory.NewCryptoListing("crypto")
	//listing.Metadata.CoinType = ""

	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(core.ErrCryptocurrencyListingCoinTypeRequired)},
	})
}
*/

/*
func TestCryptoListingsCoinDivisibilityIncorrect(t *testing.T) {
	listing := factory.NewCryptoListing("crypto")
	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, listing), 200, anyResponseJSON},
	})

	//listing.Metadata.CoinDivisibility = 1e7
	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(core.ErrListingCoinDivisibilityIncorrect)},
	})

	//listing.Metadata.CoinDivisibility = 0
	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(core.ErrListingCoinDivisibilityIncorrect)},
	})
}
*/

func TestCryptoListingsIllegalFields(t *testing.T) {
	runTest := func(listing *pb.Listing, err error) {
		runAPITests(t, apiTests{
			{"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(err)},
		})
	}

	physicalListing := factory.NewListing("physical")

	//listing := factory.NewCryptoListing("crypto")
	//listing.Metadata.PricingCurrency = &pb.CurrencyDefinition{Code: "BTC", Divisibility: 8}
	//runTest(listing, core.ErrCryptocurrencyListingIllegalField("metadata.pricingCurrency"))

	listing := factory.NewCryptoListing("crypto")
	listing.Item.Condition = "new"
	runTest(listing, repo.ErrCryptocurrencyListingIllegalField("item.condition"))

	listing = factory.NewCryptoListing("crypto")
	listing.Item.Options = physicalListing.Item.Options
	runTest(listing, repo.ErrCryptocurrencyListingIllegalField("item.options"))

	listing = factory.NewCryptoListing("crypto")
	listing.ShippingOptions = physicalListing.ShippingOptions
	runTest(listing, repo.ErrCryptocurrencyListingIllegalField("shippingOptions"))

	listing = factory.NewCryptoListing("crypto")
	listing.Coupons = physicalListing.Coupons
	/*[]*pb.Listing_Coupon{}
	sampleCoupon := new(pb.Listing_Coupon)
	sampleCoupon.Title = "sample coupon"
	sampleCoupon.Code = &pb.Listing_Coupon_DiscountCode{DiscountCode: "insider"}
	sampleCoupon.Discount = &pb.Listing_Coupon_PercentDiscount{PercentDiscount: 5}
	*/
	runTest(listing, repo.ErrCryptocurrencyListingIllegalField("coupons"))

}

func TestMarketRatePrice(t *testing.T) {
	listing := factory.NewListing("listing")
	listing.Metadata.Format = pb.Listing_Metadata_MARKET_PRICE
	listing.Item.BigPrice = "100"
	listing.Item.PriceCurrency = &pb.CurrencyDefinition{Code: "BTC", Divisibility: 8}

	runAPITests(t, apiTests{
		{"POST", "/ob/listing", jsonFor(t, listing), 500, errorResponseJSON(fmt.Errorf("validate sellable listing (listing): %s", repo.ErrMarketPriceListingIllegalField("item.bigPrice")))},
	})
}

func TestStatus(t *testing.T) {
	runAPITests(t, apiTests{
		{"GET", "/ob/status", "", 400, anyResponseJSON},
		{"GET", "/ob/status/QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG", "", 200, anyResponseJSON},
	})
}

func TestWallet(t *testing.T) {
	runAPITests(t, apiTests{
		{"GET", "/wallet/address", "", 200, walletAddressJSONResponse},
		{"GET", "/wallet/balance", "", 200, walletBalanceJSONResponse},
		{"GET", "/wallet/mnemonic", "", 200, walletMneumonicJSONResponse},
		// TODO: Test successful spend on regnet with coins
	})
}

func TestWalletSpendFailures(t *testing.T) {
	newSpendRequest := func() *core.SpendRequest {
		return &core.SpendRequest{
			CurrencyCode:           "TBTC",
			Address:                "1HYhu8e2wv19LZ2umXoo1pMiwzy2rL32UQ",
			Amount:                 "1234",
			FeeLevel:               "PRIORITY",
			RequireAssociatedOrder: false,
		}
	}

	insufficientFundsRequest := newSpendRequest()
	insufficientFundsRequest.Amount = "1700000"
	insufficientFundsResponse := APIError{Reason: core.ErrInsufficientFunds.Error()}

	invalidAmountRequest := newSpendRequest()
	invalidAmountRequest.Amount = ""
	invalidAmountResponse := APIError{Reason: core.ErrInvalidAmount.Error()}

	missingCurrencyRequest := newSpendRequest()
	missingCurrencyRequest.Currency = nil
	missingCurrencyRequest.CurrencyCode = ""
	missingCurrencyResponse := APIError{Reason: repo.ErrCurrencyDefinitionUndefined.Error()}

	invalidAddrRequest := newSpendRequest()
	invalidAddrRequest.Address = "invalid"
	invalidAddrResponse := APIError{Reason: core.ErrInvalidSpendAddress.Error()}

	runAPITests(t, apiTests{
		{
			"POST", "/wallet/spend",
			insufficientFundsRequest,
			400, insufficientFundsResponse,
		},
		{
			"POST", "/wallet/spend",
			invalidAmountRequest,
			400, invalidAmountResponse,
		},
		{
			"POST", "/wallet/spend",
			missingCurrencyRequest,
			400, missingCurrencyResponse,
		},
		{
			"POST", "/wallet/spend",
			invalidAddrRequest,
			400, invalidAddrResponse,
		},
	})
}

func TestWalletCurrencyDictionary(t *testing.T) {
	var expectedResponse, err = json.MarshalIndent(repo.AllCurrencies().AsMap(), "", "    ")
	if err != nil {
		t.Fatal(err)
	}

	runAPITests(t, apiTests{
		{"GET", "/wallet/currencies", "", 200, string(expectedResponse)},
	})
}

func TestWalletCurrencyDictionaryLookup(t *testing.T) {
	var randomLookup string
	for currency := range repo.TestnetCurrencies().AsMap() {
		// pick any currency string from the dictionary
		randomLookup = currency
		break
	}

	def, err := repo.AllCurrencies().Lookup(randomLookup)
	if err != nil {
		t.Fatalf("error looking up (%s): %s", randomLookup, err.Error())
	}
	entries := map[string]repo.CurrencyDefinition{randomLookup: def}
	expectedResponse, err := json.MarshalIndent(entries, "", "    ")
	if err != nil {
		t.Fatal(err)
	}

	runAPITests(t, apiTests{
		{"GET", fmt.Sprintf("/wallet/currencies/%s", randomLookup), "", 200, string(expectedResponse)},
		{"GET", fmt.Sprintf("/wallet/currencies/%s", "INVALID"), "", 404, errorResponseJSON(errors.New("unknown definition for INVALID"))},
	})
}

func TestExchangeRates(t *testing.T) {
	runAPITests(t, apiTests{
		{"GET", "/ob/exchangerates", "", 500, invalidCoinJSON},
		{"GET", "/ob/exchangerates/", "", 500, invalidCoinJSON},
		{"GET", "/ob/exchangerates/BTC", "", 200, anyResponseJSON},
	})
}

func TestConfig(t *testing.T) {
	runAPITests(t, apiTests{
		// TODO: Need better JSON matching
		{"GET", "/ob/config", "", 200, anyResponseJSON},
	})
}

func Test404(t *testing.T) {
	// Test undefined endpoints
	runAPITests(t, apiTests{
		{"GET", "/ob/a", "{}", 404, notFoundJSON},
		{"PUT", "/ob/a", "{}", 404, notFoundJSON},
		{"POST", "/ob/a", "{}", 404, notFoundJSON},
		{"PATCH", "/ob/a", "{}", 404, notFoundJSON},
		{"DELETE", "/ob/a", "{}", 404, notFoundJSON},
	})
}

func TestPosts(t *testing.T) {
	runAPITests(t, apiTests{
		{"GET", "/ob/posts", "", 200, `[]`},

		// Invalid creates
		{"POST", "/ob/post", `{`, 400, jsonUnexpectedEOF},

		{"GET", "/ob/posts", "", 200, `[]`},

		// Create/Get
		{"GET", "/ob/post/test1", "", 404, NotFoundJSON("Post")},
		{"POST", "/ob/post", postJSON, 200, postJSONResponse},
		{"GET", "/ob/post/test1", "", 200, anyResponseJSON},
		{"POST", "/ob/post", postUpdateJSON, 409, AlreadyExistsUsePUTJSON("Post")},

		{"GET", "/ob/posts", "", 200, anyResponseJSON},

		// Update/Get Post
		{"PUT", "/ob/post", postUpdateJSON, 200, `{}`},
		{"GET", "/ob/post/test1", "", 200, anyResponseJSON},

		// Delete/Get
		{"DELETE", "/ob/post/test1", "", 200, `{}`},
		{"DELETE", "/ob/post/test1", "", 404, NotFoundJSON("Post")},
		{"GET", "/ob/post/test1", "", 404, NotFoundJSON("Post")},

		// Mutate non-existing listings
		{"PUT", "/ob/post", postUpdateJSON, 404, NotFoundJSON("Post")},
		{"DELETE", "/ob/post/test1", "", 404, NotFoundJSON("Post")},
	})
}

func TestCloseDisputeBlocksWhenExpired(t *testing.T) {
	dbSetup := func(testRepo *test.Repository) error {
		paymentCoin := repo.CurrencyCode("BTC")
		expired := factory.NewExpiredDisputeCaseRecord()
		expired.CaseID = "expiredCase"
		expired.PaymentCoin = &paymentCoin
		for _, r := range []*repo.DisputeCaseRecord{expired} {
			if err := testRepo.DB.Cases().PutRecord(r); err != nil {
				return err
			}
			if err := testRepo.DB.Cases().UpdateBuyerInfo(r.CaseID, r.BuyerContract, []string{}, r.BuyerPayoutAddress, r.BuyerOutpoints); err != nil {
				return err
			}
		}
		return nil
	}
	expiredPostJSON := `{"orderId":"expiredCase","resolution":"","buyerPercentage":100.0,"vendorPercentage":0.0}`
	runAPITestsWithSetup(t, apiTests{
		{"POST", "/ob/closedispute", expiredPostJSON, 400, anyResponseJSON},
	}, dbSetup, nil)
}

func TestZECSalesCannotReleaseEscrow(t *testing.T) {
	sale := factory.NewSaleRecord()
	sale.Contract.VendorListings[0].Metadata.AcceptedCurrencies = []string{"ZEC"}
	sale.Contract.BuyerOrder.Payment.AmountCurrency = &pb.CurrencyDefinition{Code: "ZEC", Divisibility: 8}
	dbSetup := func(testRepo *test.Repository) error {
		if err := testRepo.DB.Sales().Put(sale.OrderID, *sale.Contract, sale.OrderState, false); err != nil {
			return err
		}
		return nil
	}
	runAPITestsWithSetup(t, apiTests{
		{"POST", "/ob/releaseescrow", fmt.Sprintf(`{"orderId":"%s"}`, sale.OrderID), 400, anyResponseJSON},
	}, dbSetup, nil)
}

func TestSalesGet(t *testing.T) {
	sale := factory.NewSaleRecord()
	sale.Contract.VendorListings[0].Metadata.AcceptedCurrencies = []string{"BTC"}
	//sale.Contract.VendorListings[0].Metadata.CoinType = "ZEC"
	sale.Contract.VendorListings[0].Metadata.ContractType = pb.Listing_Metadata_CRYPTOCURRENCY
	dbSetup := func(testRepo *test.Repository) error {
		return testRepo.DB.Sales().Put(sale.OrderID, *sale.Contract, sale.OrderState, false)
	}

	runAPITestsWithSetup(t, apiTests{
		{"GET", "/ob/sales", "", 200, anyResponseJSON},
	}, dbSetup, nil)

	respBytes, err := httpGet("/ob/sales")
	if err != nil {
		t.Fatal(err)
	}
	respObj := struct {
		Sales []repo.Sale `json:"sales"`
	}{}
	err = json.Unmarshal(respBytes, &respObj)
	if err != nil {
		t.Fatal(err)
	}

	actualSale := respObj.Sales[0]

	if actualSale.BuyerHandle != sale.Contract.BuyerOrder.BuyerID.Handle {
		t.Fatal("Incorrect buyerHandle:", actualSale.BuyerHandle, "\nwanted:", sale.Contract.BuyerOrder.BuyerID.Handle)
	}
	if actualSale.BuyerId != sale.Contract.BuyerOrder.BuyerID.PeerID {
		t.Fatal("Incorrect buyerId:", actualSale.BuyerId, "\nwanted:", sale.Contract.BuyerOrder.BuyerID.PeerID)
	}
	//if actualSale.CoinType != sale.Contract.VendorListings[0].Metadata.CoinType {
	//	t.Fatal("Incorrect coinType:", actualSale.CoinType, "\nwanted:", sale.Contract.VendorListings[0].Metadata.CoinType)
	//}
	if actualSale.OrderId != sale.OrderID {
		t.Fatal("Incorrect orderId:", actualSale.OrderId, "\nwanted:", sale.OrderID)
	}
	if actualSale.PaymentCoin != sale.Contract.VendorListings[0].Metadata.AcceptedCurrencies[0] {
		t.Fatal("Incorrect paymentCoin:", actualSale.PaymentCoin, "\nwanted:", sale.Contract.VendorListings[0].Metadata.AcceptedCurrencies[0])
	}
	if actualSale.ShippingAddress != sale.Contract.BuyerOrder.Shipping.Address {
		t.Fatal("Incorrect shippingAddress:", actualSale.ShippingAddress, "\nwanted:", sale.Contract.BuyerOrder.Shipping.Address)
	}
	if actualSale.ShippingName != sale.Contract.BuyerOrder.Shipping.ShipTo {
		t.Fatal("Incorrect shippingName:", actualSale.ShippingName, "\nwanted:", sale.Contract.BuyerOrder.Shipping.ShipTo)
	}
	if actualSale.State != sale.OrderState.String() {
		t.Fatal("Incorrect state:", actualSale.State, "\nwanted:", sale.OrderState.String())
	}
}
func TestPurchasesGet(t *testing.T) {
	purchase := factory.NewPurchaseRecord()
	purchase.Contract.VendorListings[0].Metadata.AcceptedCurrencies = []string{"BTC"}
	//purchase.Contract.VendorListings[0].Metadata.CoinType = "ZEC"
	purchase.Contract.VendorListings[0].Metadata.ContractType = pb.Listing_Metadata_CRYPTOCURRENCY
	dbSetup := func(testRepo *test.Repository) error {
		return testRepo.DB.Purchases().Put(purchase.OrderID, *purchase.Contract, purchase.OrderState, false)
	}

	runAPITestsWithSetup(t, apiTests{
		{"GET", "/ob/purchases", "", 200, anyResponseJSON},
	}, dbSetup, nil)

	respBytes, err := httpGet("/ob/purchases")
	if err != nil {
		t.Fatal(err)
	}
	respObj := struct {
		Purchases []repo.Purchase `json:"purchases"`
	}{}
	err = json.Unmarshal(respBytes, &respObj)
	if err != nil {
		t.Fatal(err)
	}

	actualPurchase := respObj.Purchases[0]

	if actualPurchase.VendorHandle != purchase.Contract.VendorListings[0].VendorID.Handle {
		t.Fatal("Incorrect vendorHandle:", actualPurchase.VendorId, "\nwanted:", purchase.Contract.VendorListings[0].VendorID.Handle)
	}
	if actualPurchase.VendorId != purchase.Contract.VendorListings[0].VendorID.PeerID {
		t.Fatal("Incorrect vendorId:", actualPurchase.VendorId, "\nwanted:", purchase.Contract.VendorListings[0].VendorID.PeerID)
	}
	//if actualPurchase.CoinType != purchase.Contract.VendorListings[0].Metadata.CoinType {
	//	t.Fatal("Incorrect coinType:", actualPurchase.CoinType, "\nwanted:", purchase.Contract.VendorListings[0].Metadata.CoinType)
	//}
	if actualPurchase.OrderId != purchase.OrderID {
		t.Fatal("Incorrect orderId:", actualPurchase.OrderId, "\nwanted:", purchase.OrderID)
	}
	if actualPurchase.PaymentCoin != purchase.Contract.VendorListings[0].Metadata.AcceptedCurrencies[0] {
		t.Fatal("Incorrect paymentCoin:", actualPurchase.PaymentCoin, "\nwanted:", purchase.Contract.VendorListings[0].Metadata.AcceptedCurrencies[0])
	}
	if actualPurchase.ShippingAddress != purchase.Contract.BuyerOrder.Shipping.Address {
		t.Fatal("Incorrect shippingAddress:", actualPurchase.ShippingAddress, "\nwanted:", purchase.Contract.BuyerOrder.Shipping.Address)
	}
	if actualPurchase.ShippingName != purchase.Contract.BuyerOrder.Shipping.ShipTo {
		t.Fatal("Incorrect shippingName:", actualPurchase.ShippingName, "\nwanted:", purchase.Contract.BuyerOrder.Shipping.ShipTo)
	}
	if actualPurchase.State != purchase.OrderState.String() {
		t.Fatal("Incorrect state:", actualPurchase.State, "\nwanted:", purchase.OrderState.String())
	}
}

func TestCasesGet(t *testing.T) {
	paymentCoinCode := repo.CurrencyCode("BTC")
	disputeCaseRecord := factory.NewDisputeCaseRecord()
	disputeCaseRecord.BuyerContract.VendorListings[0].Metadata.AcceptedCurrencies = []string{"BTC"}
	//disputeCaseRecord.BuyerContract.VendorListings[0].Metadata.CoinType = "ZEC"
	disputeCaseRecord.BuyerContract.VendorListings[0].Metadata.ContractType = pb.Listing_Metadata_CRYPTOCURRENCY
	disputeCaseRecord.CoinType = "ZEC"
	disputeCaseRecord.PaymentCoin = &paymentCoinCode
	dbSetup := func(testRepo *test.Repository) error {
		return testRepo.DB.Cases().PutRecord(disputeCaseRecord)
	}

	runAPITestsWithSetup(t, apiTests{
		{"GET", "/ob/cases", "", 200, anyResponseJSON},
	}, dbSetup, nil)

	respBytes, err := httpGet("/ob/cases")
	if err != nil {
		t.Fatal(err)
	}
	respObj := struct {
		Cases []repo.Case `json:"cases"`
	}{}
	err = json.Unmarshal(respBytes, &respObj)
	if err != nil {
		t.Fatal(err)
	}

	actualCase := respObj.Cases[0]

	//if actualCase.CoinType != disputeCaseRecord.BuyerContract.VendorListings[0].Metadata.CoinType {
	//	t.Fatal("Incorrect coinType:", actualCase.CoinType, "\nwanted:", disputeCaseRecord.BuyerContract.VendorListings[0].Metadata.CoinType)
	//}
	if actualCase.PaymentCoin != disputeCaseRecord.BuyerContract.VendorListings[0].Metadata.AcceptedCurrencies[0] {
		t.Fatal("Incorrect paymentCoin:", actualCase.PaymentCoin, "\nwanted:", disputeCaseRecord.BuyerContract.VendorListings[0].Metadata.AcceptedCurrencies[0])
	}
	if actualCase.State != disputeCaseRecord.OrderState.String() {
		t.Fatal("Incorrect state:", actualCase.State, "\nwanted:", disputeCaseRecord.OrderState.String())
	}
}

func TestNotificationsAreReturnedInExpectedOrder(t *testing.T) {
	const sameTimestampsAreReturnedInReverse = `{
    "notifications": [
        {
            "notification": {
                "notificationId": "notif3",
                "peerId": "somepeerid",
                "type": "follow"
            },
            "read": false,
	    "timestamp": "1996-07-17T23:15:45Z",
            "type": "follow"
        },
        {
            "notification": {
                "notificationId": "notif2",
                "peerId": "somepeerid",
                "type": "follow"
            },
            "read": false,
	    "timestamp": "1996-07-17T23:15:45Z",
            "type": "follow"
        },
        {
            "notification": {
                "notificationId": "notif1",
                "peerId": "somepeerid",
                "type": "follow"
            },
            "read": false,
	    "timestamp": "1996-07-17T23:15:45Z",
            "type": "follow"
        }
    ],
    "total": 3,
    "unread": 3
}`

	const sameTimestampsAreReturnedInReverseAndRespectOffsetID = `{
    "notifications": [
        {
            "notification": {
                "notificationId": "notif2",
                "peerId": "somepeerid",
                "type": "follow"
            },
            "read": false,
            "timestamp": "1996-07-17T23:15:45Z",
            "type": "follow"
        },
        {
            "notification": {
                "notificationId": "notif1",
                "peerId": "somepeerid",
                "type": "follow"
            },
            "read": false,
            "timestamp": "1996-07-17T23:15:45Z",
            "type": "follow"
        }
    ],
    "total": 0,
    "unread": 3
}`
	var (
		createdAt = time.Unix(837645345, 0)
		notif1    = &repo.Notification{
			ID:           "notif1",
			CreatedAt:    repo.NewAPITime(createdAt),
			NotifierType: repo.NotifierTypeFollowNotification,
			NotifierData: &repo.FollowNotification{
				ID:     "notif1",
				Type:   repo.NotifierTypeFollowNotification,
				PeerId: "somepeerid",
			},
		}
		notif2 = &repo.Notification{
			ID:           "notif2",
			CreatedAt:    repo.NewAPITime(createdAt),
			NotifierType: repo.NotifierTypeFollowNotification,
			NotifierData: &repo.FollowNotification{
				ID:     "notif2",
				Type:   repo.NotifierTypeFollowNotification,
				PeerId: "somepeerid",
			},
		}
		notif3 = &repo.Notification{
			ID:           "notif3",
			CreatedAt:    repo.NewAPITime(createdAt),
			NotifierType: repo.NotifierTypeFollowNotification,
			NotifierData: &repo.FollowNotification{
				ID:     "notif3",
				Type:   repo.NotifierTypeFollowNotification,
				PeerId: "somepeerid",
			},
		}
	)
	dbSetup := func(testRepo *test.Repository) error {
		for _, n := range []*repo.Notification{notif1, notif2, notif3} {
			if err := testRepo.DB.Notifications().PutRecord(n); err != nil {
				return err
			}
		}
		return nil
	}
	dbTeardown := func(testRepo *test.Repository) error {
		for _, n := range []*repo.Notification{notif1, notif2, notif3} {
			if err := testRepo.DB.Notifications().Delete(n.GetID()); err != nil {
				return err
			}
		}
		return nil
	}
	runAPITestsWithSetup(t, apiTests{
		{"GET", "/ob/notifications?limit=-1", "", 200, sameTimestampsAreReturnedInReverse},
		{"GET", "/ob/notifications?limit=-1&offsetId=notif3", "", 200, sameTimestampsAreReturnedInReverseAndRespectOffsetID},
	}, dbSetup, dbTeardown)
}

func TestResendOrderMessage(t *testing.T) {
	runAPITests(t, apiTests{
		// supports missing messageType
		{"POST", "/ob/resendordermessage", `{"orderID":"123"}`, http.StatusBadRequest, errorResponseJSON(fmt.Errorf("missing messageType argument"))},
		// supports missing order ID
		{"POST", "/ob/resendordermessage", `{"messageType":"nonexistant"}`, http.StatusBadRequest, errorResponseJSON(fmt.Errorf("missing orderID argument"))},
		// supports nonexistant message types
		{"POST", "/ob/resendordermessage", `{"orderID":"123","messageType":"nonexistant"}`, http.StatusBadRequest, errorResponseJSON(fmt.Errorf("unknown messageType (nonexistant)"))},
		// supports downcased message types, expected not to find order ID
		{"POST", "/ob/resendordermessage", `{"orderID":"123","messageType":"order"}`, http.StatusInternalServerError, errorResponseJSON(fmt.Errorf("unable to find message for order ID (123) and message type (ORDER)"))},
	})
}

// TODO: Make NewDisputeCaseRecord return a valid fixture for this valid case to work
//func TestCloseDisputeReturnsOK(t *testing.T) {
//dbSetup := func(testRepo *test.Repository) error {
//nonexpired := factory.NewDisputeCaseRecord()
//nonexpired.CaseID = "nonexpiredCase"
//for _, r := range []*repo.DisputeCaseRecord{nonexpired} {
//if err := testRepo.DB.Cases().PutRecord(r); err != nil {
//return err
//}
//if err := testRepo.DB.Cases().UpdateBuyerInfo(r.CaseID, r.BuyerContract, []string{}, r.BuyerPayoutAddress, r.BuyerOutpoints); err != nil {
//return err
//}
//}
//return nil
//}
//nonexpiredPostJSON := `{"orderId":"nonexpiredCase","resolution":"","buyerPercentage":100.0,"vendorPercentage":0.0}`
//runAPITestsWithSetup(t, apiTests{
//{"POST", "/ob/profile", moderatorProfileJSON, 200, anyResponseJSON},
//{"POST", "/ob/closedispute", nonexpiredPostJSON, 200, anyResponseJSON},
//}, dbSetup, nil)
//}
