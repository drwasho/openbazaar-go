package repo

import (
	"encoding/json"
	"fmt"
)

type (
	ListingPrice struct {
		Amount   CurrencyValue `json:"amount"`
		Modifier float32       `json:"modifier"`
	}

	ListingThumbnail struct {
		Tiny   string `json:"tiny"`
		Small  string `json:"small"`
		Medium string `json:"medium"`
	}

	// ListingIndexData reprents a single node in the Listing index
	ListingIndexData struct {
		Hash               string           `json:"hash"`
		Slug               string           `json:"slug"`
		Title              string           `json:"title"`
		Categories         []string         `json:"categories"`
		NSFW               bool             `json:"nsfw"`
		ContractType       string           `json:"contractType"`
		Description        string           `json:"description"`
		Thumbnail          ListingThumbnail `json:"thumbnail"`
		Price              ListingPrice     `json:"price"`
		ShipsTo            []string         `json:"shipsTo"`
		FreeShipping       []string         `json:"freeShipping"`
		Language           string           `json:"language"`
		AverageRating      float32          `json:"averageRating"`
		RatingCount        uint32           `json:"ratingCount"`
		ModeratorIDs       []string         `json:"moderators"`
		AcceptedCurrencies []string         `json:"acceptedCurrencies"`
	}
)

// UnmarshalJSONSignedListingIndex consumes a []byte payload of JSON representing
// a list of SignedListings and returns a parsed instance or an error if the payload
// cannot be successfully parsed
func UnmarshalJSONSignedListingIndex(data []byte) ([]ListingIndexData, error) {
	var (
		rawIndex     []json.RawMessage
		listingIndex []ListingIndexData
	)
	if err := json.Unmarshal(data, &rawIndex); err != nil {
		return nil, err
	}

	// best effort parse
	// TODO: intelligently parse payload based on
	// detection of the correct version.
	for _, listingJSON := range rawIndex {
		l, err := parseUnknownData(listingJSON)
		if err != nil {
			return nil, err
		}
		listingIndex = append(listingIndex, l)
	}
	return listingIndex, nil
}

func parseUnknownData(data []byte) (ListingIndexData, error) {
	sl, err := parseV5Data(data)
	if err == nil {
		return sl, nil
	} else {
		log.Warningf("failed attempt to parse v5 listing index: %s", err)
	}
	sl, err = parseV4Data(data)
	if err == nil {
		return sl, nil
	} else {
		log.Warningf("failed attempt to parse v4 listing index: %s", err)
	}
	return ListingIndexData{}, fmt.Errorf("failed parsing listing in index: %s", err)
}

func parseV5Data(data []byte) (ListingIndexData, error) {
	var v5 ListingIndexData
	if err := json.Unmarshal(data, &v5); err != nil {
		return ListingIndexData{}, err
	}
	return v5, nil
}

func parseV4Data(data []byte) (ListingIndexData, error) {
	var v4 struct {
		Hash         string           `json:"hash"`
		Slug         string           `json:"slug"`
		Title        string           `json:"title"`
		Categories   []string         `json:"categories"`
		NSFW         bool             `json:"nsfw"`
		ContractType string           `json:"contractType"`
		Description  string           `json:"description"`
		Thumbnail    ListingThumbnail `json:"thumbnail"`
		Price        struct {
			CurrencyCode string  `json:"currencyCode"`
			Amount       uint    `json:"amount"`
			Modifier     float32 `json:"modifier"`
		} `json:"price"`
		ShipsTo            []string `json:"shipsTo"`
		FreeShipping       []string `json:"freeShipping"`
		Language           string   `json:"language"`
		AverageRating      float32  `json:"averageRating"`
		RatingCount        uint32   `json:"ratingCount"`
		ModeratorIDs       []string `json:"moderators"`
		AcceptedCurrencies []string `json:"acceptedCurrencies"`
		CoinType           string   `json:"coinType"`
	}
	if err := json.Unmarshal(data, &v4); err != nil {
		return ListingIndexData{}, err
	}
	priceDef, err := AllCurrencies().Lookup(v4.Price.CurrencyCode)
	if err != nil {
		return ListingIndexData{}, err
	}
	priceValue, err := NewCurrencyValueFromUint(uint64(v4.Price.Amount), priceDef)
	if err != nil {
		return ListingIndexData{}, err
	}
	if v4.CoinType != "" && v4.CoinType != v4.Price.CurrencyCode {
		log.Warningf("parsing v4 listing: ignoring inconsistent coinType (%s), using price currencyCode (%s)", v4.CoinType, v4.Price.CurrencyCode)
	}
	return ListingIndexData{
		Hash:         v4.Hash,
		Slug:         v4.Slug,
		Title:        v4.Title,
		Categories:   v4.Categories,
		NSFW:         v4.NSFW,
		ContractType: v4.ContractType,
		Description:  v4.Description,
		Thumbnail:    v4.Thumbnail,
		Price: ListingPrice{
			Modifier: v4.Price.Modifier,
			Amount:   *priceValue,
		},
		ShipsTo:            v4.ShipsTo,
		FreeShipping:       v4.FreeShipping,
		Language:           v4.Language,
		AverageRating:      v4.AverageRating,
		RatingCount:        v4.RatingCount,
		ModeratorIDs:       v4.ModeratorIDs,
		AcceptedCurrencies: v4.AcceptedCurrencies,
	}, nil
}
