package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	cid "gx/ipfs/QmNp85zy9RLrQ5oQD4hPyS39ezrrXpcaa7R4Y9kxdWQLLQ/go-cid"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"time"

	"github.com/OpenBazaar/jsonpb"
	"github.com/OpenBazaar/openbazaar-go/ipfs"
	"github.com/OpenBazaar/openbazaar-go/pb"
	"github.com/OpenBazaar/openbazaar-go/repo"
	"github.com/golang/protobuf/proto"
	"github.com/microcosm-cc/bluemonday"
)

type classifiedData struct {
	Hash          string    `json:"hash"`
	Slug          string    `json:"slug"`
	Title         string    `json:"title"`
	Categories    []string  `json:"categories"`
	NSFW          bool      `json:"nsfw"`
	ContractType  string    `json:"contractType"`
	Description   string    `json:"description"`
	Thumbnail     thumbnail `json:"thumbnail"`
	Price         price     `json:"price"`
	ShipsTo       []string  `json:"shipsTo"`
	FreeShipping  []string  `json:"freeShipping"`
	Language      string    `json:"language"`
}

// Add our identity to the classified and sign it
func (n *OpenBazaarNode) SignClassified(classified *pb.Classified) (*pb.SignedClassified, error) {

	sl := new(pb.SignedClassified)

	// Set crypto currency
	classified.Metadata.AcceptedCurrencies = []string{strings.ToUpper(n.Wallet.CurrencyCode())}

	// Sanitize a few critical fields
	if classified.Item == nil {
		return sl, errors.New("No item in classified")
	}
	sanitizer := bluemonday.UGCPolicy()
	for _, so := range classified.ShippingOptions {
		so.Name = sanitizer.Sanitize(so.Name)
	}

	// Check the classified data is correct for continuing
	if err := validateClassfied(classified, testnet); err != nil {
		return sl, err
	}

	// Set classified version
	classified.Metadata.Version = ClassifiedVersion

	// Add the vendor ID to the classified
	id := new(pb.ID)
	id.PeerID = n.IpfsNode.Identity.Pretty()
	pubkey, err := n.IpfsNode.PrivateKey.GetPublic().Bytes()
	if err != nil {
		return sl, err
	}
	profile, err := n.GetProfile()
	if err == nil {
		id.Handle = profile.Handle
	}
	p := new(pb.ID_Pubkeys)
	p.Identity = pubkey
	ecPubKey, err := n.Wallet.MasterPublicKey().ECPubKey()
	if err != nil {
		return sl, err
	}
	p.Bitcoin = ecPubKey.SerializeCompressed()
	id.Pubkeys = p
	classified.VendorID = id

	// Sign the GUID with the Bitcoin key
	ecPrivKey, err := n.Wallet.MasterPrivateKey().ECPrivKey()
	if err != nil {
		return sl, err
	}
	sig, err := ecPrivKey.Sign([]byte(id.PeerID))
	id.BitcoinSig = sig.Serialize()

	// Sign classified
	serializedClassified, err := proto.Marshal(classified)
	if err != nil {
		return sl, err
	}
	idSig, err := n.IpfsNode.PrivateKey.Sign(serializedClassified)
	if err != nil {
		return sl, err
	}
	sl.Classified = classified
	sl.Signature = idSig
	return sl, nil
}

func (n *OpenBazaarNode) UpdateClassifiedIndex(classified *pb.SignedClassified) error {
	ld, err := n.extractClassifiedData(classified)
	if err != nil {
		return err
	}
	index, err := n.getClassifiedIndex()
	if err != nil {
		return err
	}
	return n.updateClassifiedOnDisk(index, ld, false)
}

func (n *OpenBazaarNode) extractClassifiedData(classified *pb.SignedClassified) (classifiedData, error) {
	classifiedPath := path.Join(n.RepoPath, "root", "classifieds", classified.Classified.Slug+".json")

	classifiedHash, err := ipfs.GetHashOfFile(n.Context, classifiedPath)
	if err != nil {
		return classifiedData{}, err
	}

	descriptionLength := len(classified.Classified.Item.Description)
	if descriptionLength > ShortDescriptionLength {
		descriptionLength = ShortDescriptionLength
	}

	contains := func(s []string, e string) bool {
		for _, a := range s {
			if a == e {
				return true
			}
		}
		return false
	}

	shipsTo := []string{}
	freeShipping := []string{}
	for _, shippingOption := range classified.Classified.ShippingOptions {
		for _, region := range shippingOption.Regions {
			if !contains(shipsTo, region.String()) {
				shipsTo = append(shipsTo, region.String())
			}
		}
	}

	ld := classifiedData{
		Hash:         classifiedHash,
		Slug:         classified.Classified.Slug,
		Title:        classified.Classified.Item.Title,
		Categories:   classified.Classified.Item.Categories,
		NSFW:         classified.Classified.Item.Nsfw,
		ContractType: classified.Classified.Metadata.ContractType.String(),
		Description:  classified.Classified.Item.Description[:descriptionLength],
		Thumbnail:    thumbnail{classified.Classified.Item.Images[0].Tiny, classified.Classified.Item.Images[0].Small, classified.Classified.Item.Images[0].Medium},
		Price:        price{classified.Classified.Metadata.PricingCurrency, classified.Classified.Item.Price},
		ShipsTo:      shipsTo,
		FreeShipping: freeShipping,
		Language:     classified.Classified.Metadata.Language,
	}
	return ld, nil
}

func (n *OpenBazaarNode) getClassifiedIndex() ([]classifiedData, error) {
	indexPath := path.Join(n.RepoPath, "root", "classifieds.json")

	var index []classifiedData

	_, ferr := os.Stat(indexPath)
	if !os.IsNotExist(ferr) {
		// Read existing file
		file, err := ioutil.ReadFile(indexPath)
		if err != nil {
			return index, err
		}
		err = json.Unmarshal(file, &index)
		if err != nil {
			return index, err
		}
	}
	return index, nil
}

// Update the classifieds.json file in the classifieds directory
func (n *OpenBazaarNode) updateClassifiedOnDisk(index []classifiedData, ld classifiedData) error {
	indexPath := path.Join(n.RepoPath, "root", "classifieds.json")
	// Check to see if the classified we are adding already exists in the list. If so delete it.
	for i, d := range index {
		if d.Slug != ld.Slug {
			continue
		}

		if len(index) == 1 {
			index = []classifiedData{}
			break
		}
		index = append(index[:i], index[i+1:]...)
	}

	// Append our classified with the new hash to the list
	index = append(index, ld)

	// Write it back to file
	f, err := os.Create(indexPath)
	if err != nil {
		return err
	}
	defer f.Close()

	j, jerr := json.MarshalIndent(index, "", "    ")
	if jerr != nil {
		return jerr
	}
	_, werr := f.Write(j)
	if werr != nil {
		return werr
	}
	return nil
}

// Update the hashes in the classifieds.json file
func (n *OpenBazaarNode) UpdateClassifiedHashes(hashes map[string]string) error {
	indexPath := path.Join(n.RepoPath, "root", "classifieds.json")

	var index []classifiedData

	_, ferr := os.Stat(indexPath)
	if os.IsNotExist(ferr) {
		return nil
	}
	// Read existing file
	file, err := ioutil.ReadFile(indexPath)
	if err != nil {
		return err
	}
	err = json.Unmarshal(file, &index)
	if err != nil {
		return err
	}

	// Update hashes
	for _, d := range index {
		hash, ok := hashes[d.Slug]
		if ok {
			d.Hash = hash
		}
	}

	// Write it back to file
	f, err := os.Create(indexPath)
	defer f.Close()
	if err != nil {
		return err
	}

	j, jerr := json.MarshalIndent(index, "", "    ")
	if jerr != nil {
		return jerr
	}
	_, werr := f.Write(j)
	if werr != nil {
		return werr
	}
	return nil
}

// Return the current number of classifieds
func (n *OpenBazaarNode) GetClassifiedCount() int {
	indexPath := path.Join(n.RepoPath, "root", "classifieds.json")

	// Read existing file
	file, err := ioutil.ReadFile(indexPath)
	if err != nil {
		return 0
	}

	var index []classifiedData
	err = json.Unmarshal(file, &index)
	if err != nil {
		return 0
	}
	return len(index)
}

// Deletes the classified directory, removes the classified from the index, and deletes the inventory
func (n *OpenBazaarNode) DeleteClassified(slug string) error {
	toDelete := path.Join(n.RepoPath, "root", "classifieds", slug+".json")
	err := os.Remove(toDelete)
	if err != nil {
		return err
	}
	var index []classifiedData
	indexPath := path.Join(n.RepoPath, "root", "classifieds.json")
	_, ferr := os.Stat(indexPath)
	if !os.IsNotExist(ferr) {
		// Read existing file
		file, err := ioutil.ReadFile(indexPath)
		if err != nil {
			return err
		}
		err = json.Unmarshal(file, &index)
		if err != nil {
			return err
		}
	}

	// Check to see if the slug exists in the list. If so delete it.
	for i, d := range index {
		if d.Slug != slug {
			continue
		}

		if len(index) == 1 {
			index = []classifiedData{}
			break
		}
		index = append(index[:i], index[i+1:]...)
	}

	// Write the index back to file
	f, err := os.Create(indexPath)
	defer f.Close()
	if err != nil {
		return err
	}

	j, jerr := json.MarshalIndent(index, "", "    ")
	if jerr != nil {
		return jerr
	}
	_, werr := f.Write(j)
	if werr != nil {
		return werr
	}

	return n.updateProfileCounts()
}

func (n *OpenBazaarNode) GetClassifieds() ([]byte, error) {
	indexPath := path.Join(n.RepoPath, "root", "classifieds.json")
	file, err := ioutil.ReadFile(indexPath)
	if os.IsNotExist(err) {
		return []byte("[]"), nil
	} else if err != nil {
		return nil, err
	}

	// Unmarshal the index to check if file contains valid json
	var index []classifiedData
	err = json.Unmarshal(file, &index)
	if err != nil {
		return nil, err
	}

	// Return bytes read from file
	return file, nil
}

func (n *OpenBazaarNode) GetClassifiedFromHash(hash string) (*pb.SignedClassified, error) {
	// Read classifieds.json
	indexPath := path.Join(n.RepoPath, "root", "classifieds.json")
	file, err := ioutil.ReadFile(indexPath)
	if err != nil {
		return nil, err
	}

	// Unmarshal the index
	var index []classifiedData
	err = json.Unmarshal(file, &index)
	if err != nil {
		return nil, err
	}

	// Extract slug that matches hash
	var slug string
	for _, data := range index {
		if data.Hash == hash {
			slug = data.Slug
			break
		}
	}

	if slug == "" {
		return nil, errors.New("Classified does not exist")
	}
	return n.GetClassifiedFromSlug(slug)
}

func (n *OpenBazaarNode) GetClassifiedFromSlug(slug string) (*pb.SignedClassified, error) {
	// Read classified file
	classifiedPath := path.Join(n.RepoPath, "root", "classifieds", slug+".json")
	file, err := ioutil.ReadFile(classifiedPath)
	if err != nil {
		return nil, err
	}

	// Unmarshal classified
	sl := new(pb.SignedClassified)
	err = jsonpb.UnmarshalString(string(file), sl)
	if err != nil {
		return nil, err
	}

	return sl, nil
}

/* Performs a ton of checks to make sure the classified is formatted correctly. This function needs to be maintained in conjunction with classifieds.proto */
func validateClassified(classified *pb.Classified) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
		}
	}()

	// Slug
	if classified.Slug == "" {
		return errors.New("Slug must not be empty")
	}
	if len(classified.Slug) > SentenceMaxCharacters {
		return fmt.Errorf("Slug is longer than the max of %d", SentenceMaxCharacters)
	}
	if strings.Contains(classified.Slug, " ") {
		return errors.New("Slugs cannot contain spaces")
	}
	if strings.Contains(classified.Slug, "/") {
		return errors.New("Slugs cannot contain file separators")
	}

	// Metadata
	if classified.Metadata == nil {
		return errors.New("Missing required field: Metadata")
	}
	if classified.Metadata.ContractType > pb.Classified_Metadata_SERVICE {
		return errors.New("Invalid contract type")
	}
	if classified.Metadata.Format > pb.Classified_Metadata_AUCTION {
		return errors.New("Invalid classified format")
	}
	if classified.Metadata.Expiry == nil {
		return errors.New("Missing required field: Expiry")
	}
	if time.Unix(classified.Metadata.Expiry.Seconds, 0).Before(time.Now()) {
		return errors.New("Classified expiration must be in the future")
	}
	if classified.Metadata.PricingCurrency == "" {
		return errors.New("Classified pricing currency code must not be empty")
	}
	if len(classified.Metadata.PricingCurrency) > WordMaxCharacters {
		return fmt.Errorf("PricingCurrency is longer than the max of %d characters", WordMaxCharacters)
	}
	if len(classified.Metadata.Language) > WordMaxCharacters {
		return fmt.Errorf("Language is longer than the max of %d characters", WordMaxCharacters)
	}

	if len(classified.Metadata.AcceptedCurrencies) == 0 {
		return errors.New("At least one accepted currency must be provided")
	}
	if len(classified.Metadata.AcceptedCurrencies) > MaxListItems {
		return fmt.Errorf("AcceptedCurrencies is longer than the max of %d currencies", MaxListItems)
	}
	for _, c := range classified.Metadata.AcceptedCurrencies {
		if len(c) > WordMaxCharacters {
			return fmt.Errorf("Accepted currency is longer than the max of %d characters", WordMaxCharacters)
		}
	}

	// Item
	if classified.Item.Title == "" {
		return errors.New("Classified must have a title")
	}
	if classified.Item.Price == 0 {
		return errors.New("Zero price classifieds are not allowed")
	}
	if len(classified.Item.Title) > TitleMaxCharacters {
		return fmt.Errorf("Title is longer than the max of %d characters", TitleMaxCharacters)
	}
	if len(classified.Item.Description) > DescriptionMaxCharacters {
		return fmt.Errorf("Description is longer than the max of %d characters", DescriptionMaxCharacters)
	}
	if len(classified.Item.ProcessingTime) > SentenceMaxCharacters {
		return fmt.Errorf("Processing time length must be less than the max of %d", SentenceMaxCharacters)
	}
	if len(classified.Item.Tags) > MaxTags {
		return fmt.Errorf("Number of tags exceeds the max of %d", MaxTags)
	}
	for _, tag := range classified.Item.Tags {
		if tag == "" {
			return errors.New("Tags must not be empty")
		}
		if len(tag) > WordMaxCharacters {
			return fmt.Errorf("Tags must be less than max of %d", WordMaxCharacters)
		}
	}
	if len(classified.Item.Images) == 0 {
		return errors.New("Classified must contain at least one image")
	}
	if len(classified.Item.Images) > MaxListItems {
		return fmt.Errorf("Number of classified images is greater than the max of %d", MaxListItems)
	}
	for _, img := range classified.Item.Images {
		_, err := cid.Decode(img.Tiny)
		if err != nil {
			return errors.New("Tiny image hashes must be properly formatted CID")
		}
		_, err = cid.Decode(img.Small)
		if err != nil {
			return errors.New("Small image hashes must be properly formatted CID")
		}
		_, err = cid.Decode(img.Medium)
		if err != nil {
			return errors.New("Medium image hashes must be properly formatted CID")
		}
		_, err = cid.Decode(img.Large)
		if err != nil {
			return errors.New("Large image hashes must be properly formatted CID")
		}
		_, err = cid.Decode(img.Original)
		if err != nil {
			return errors.New("Original image hashes must be properly formatted CID")
		}
		if img.Filename == "" {
			return errors.New("Image file names must not be nil")
		}
		if len(img.Filename) > FilenameMaxCharacters {
			return fmt.Errorf("Image filename length must be less than the max of %d", FilenameMaxCharacters)
		}
	}
	if len(classified.Item.Categories) > MaxCategories {
		return fmt.Errorf("Number of categories must be less than max of %d", MaxCategories)
	}
	for _, category := range classified.Item.Categories {
		if category == "" {
			return errors.New("Categories must not be nil")
		}
		if len(category) > WordMaxCharacters {
			return fmt.Errorf("Category length must be less than the max of %d", WordMaxCharacters)
		}
	}
	if len(classified.Item.Condition) > SentenceMaxCharacters {
		return fmt.Errorf("Condition length must be less than the max of %d", SentenceMaxCharacters)
	}

	// ShippingOptions
	if classified.Metadata.ContractType == pb.Classified_Metadata_PHYSICAL_GOOD && len(classified.ShippingOptions) == 0 {
		return errors.New("Must be at least one shipping option for a physical good")
	}
	if len(classified.ShippingOptions) > MaxListItems {
		return fmt.Errorf("Number of shipping options is greater than the max of %d", MaxListItems)
	}
	var shippingTitles []string
	for _, shippingOption := range classified.ShippingOptions {
		if shippingOption.Name == "" {
			return errors.New("Shipping option title name must not be empty")
		}
		if len(shippingOption.Name) > WordMaxCharacters {
			return fmt.Errorf("Shipping option service length must be less than the max of %d", WordMaxCharacters)
		}
		for _, t := range shippingTitles {
			if t == shippingOption.Name {
				return errors.New("Shipping option titles must be unique")
			}
		}
		shippingTitles = append(shippingTitles, shippingOption.Name)
		if shippingOption.Type > pb.Classified_ShippingOption_FIXED_PRICE {
			return errors.New("Unkown shipping option type")
		}
		if len(shippingOption.Regions) == 0 {
			return errors.New("Shipping options must specify at least one region")
		}
		for _, region := range shippingOption.Regions {
			if int(region) == 0 {
				return errors.New("Shipping region cannot be NA")
			} else if int(region) > 246 && int(region) != 500 {
				return errors.New("Invalid shipping region")
			}

		}
		if len(shippingOption.Regions) > MaxCountryCodes {
			return fmt.Errorf("Number of shipping regions is greater than the max of %d", MaxCountryCodes)
		}
	}

	// TermsAndConditions
	if len(classified.TermsAndConditions) > PolicyMaxCharacters {
		return fmt.Errorf("Terms and conditions length must be less than the max of %d", PolicyMaxCharacters)
	}

	// RefundPolicy
	if len(classified.RefundPolicy) > PolicyMaxCharacters {
		return fmt.Errorf("Refun policy length must be less than the max of %d", PolicyMaxCharacters)
	}

	return nil
}

func verifySignaturesOnClassfied(sl *pb.SignedClassified) error {
	// Verify identity signature on classified
	if err := verifySignature(
		sl.Classified,
		sl.Classified.VendorID.Pubkeys.Identity,
		sl.Signature,
		sl.Classified.VendorID.PeerID,
	); err != nil {
		switch err.(type) {
		case noSigError:
			return errors.New("Contract does not contain classified signature")
		case invalidSigError:
			return errors.New("Vendor's identity signature on classified failed to verify")
		case matchKeyError:
			return errors.New("Public key in order does not match reported buyer ID")
		default:
			return err
		}
	}

	// Verify the bitcoin signature in the ID
	if err := verifyBitcoinSignature(
		sl.Classified.VendorID.Pubkeys.Bitcoin,
		sl.Classified.VendorID.BitcoinSig,
		sl.Classified.VendorID.PeerID,
	); err != nil {
		switch err.(type) {
		case invalidSigError:
			return errors.New("Vendor's bitcoin signature on GUID failed to verify")
		default:
			return err
		}
	}
	return nil
}