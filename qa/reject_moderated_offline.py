import requests
import json
import time
from collections import OrderedDict
from test_framework.test_framework import OpenBazaarTestFramework, TestFailure


class RejectModeratedOffline(OpenBazaarTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 4

    def run_test(self):
        alice = self.nodes[1]
        bob = self.nodes[2]
        charlie = self.nodes[3]

        # generate some coins and send them to bob
        time.sleep(3)
        api_url = bob["gateway_url"] + "wallet/address/" + self.cointype
        r = requests.get(api_url)
        if r.status_code == 200:
            resp = json.loads(r.text)
            address = resp["address"]
        elif r.status_code == 404:
            raise TestFailure("RejectModeratedOffline - FAIL: Address endpoint not found")
        else:
            raise TestFailure("RejectModeratedOffline - FAIL: Unknown response")
        self.send_bitcoin_cmd("sendtoaddress", address, 10)
        time.sleep(20)

        # create a profile for charlie
        pro = {"name": "Charlie"}
        api_url = charlie["gateway_url"] + "ob/profile"
        r = requests.post(api_url, data=json.dumps(pro, indent=4))
        if r.status_code == 404:
            raise TestFailure("PurchaseModeratedOnlineTest - FAIL: Profile post endpoint not found")
        elif r.status_code != 200:
            resp = json.loads(r.text)
            raise TestFailure("PurchaseModeratedOnlineTest - FAIL: Profile POST failed. Reason: %s", resp["reason"])
        time.sleep(4)

        # make charlie a moderator
        with open('testdata/'+ self.moderator_version +'/moderation.json') as listing_file:
            moderation_json = json.load(listing_file, object_pairs_hook=OrderedDict)
        api_url = charlie["gateway_url"] + "ob/moderator"
        r = requests.put(api_url, data=json.dumps(moderation_json, indent=4))
        if r.status_code == 404:
            raise TestFailure("PurchaseModeratedOnlineTest - FAIL: Moderator post endpoint not found")
        elif r.status_code != 200:
            resp = json.loads(r.text)
            raise TestFailure("PurchaseModeratedOnlineTest - FAIL: Moderator POST failed. Reason: %s", resp["reason"])
        moderatorId = charlie["peerId"]
        time.sleep(4)

        # post profile for alice
        with open('testdata/'+ self.vendor_version +'/profile.json') as profile_file:
            profile_json = json.load(profile_file, object_pairs_hook=OrderedDict)
        api_url = alice["gateway_url"] + "ob/profile"
        requests.post(api_url, data=json.dumps(profile_json, indent=4))

        # post listing to alice
        with open('testdata/'+ self.vendor_version +'/listing.json') as listing_file:
            listing_json = json.load(listing_file, object_pairs_hook=OrderedDict)
        if self.vendor_version == 4:
            listing_json["metadata"]["priceCurrency"] = "t" + self.cointype
        else:
            listing_json["item"]["priceCurrency"]["code"] = "t" + self.cointype
        listing_json["metadata"]["acceptedCurrencies"] = ["t" + self.cointype]

        listing_json["moderators"] = [moderatorId]
        api_url = alice["gateway_url"] + "ob/listing"
        r = requests.post(api_url, data=json.dumps(listing_json, indent=4))
        if r.status_code == 404:
            raise TestFailure("RejectModeratedOffline - FAIL: Listing post endpoint not found")
        elif r.status_code != 200:
            resp = json.loads(r.text)
            raise TestFailure("RejectModeratedOffline - FAIL: Listing POST failed. Reason: %s", resp["reason"])
        time.sleep(4)

        # get listing hash
        api_url = alice["gateway_url"] + "ob/listings/" + alice["peerId"]
        r = requests.get(api_url)
        if r.status_code != 200:
            raise TestFailure("RejectModeratedOffline - FAIL: Couldn't get listing index")
        resp = json.loads(r.text)
        listingId = resp[0]["hash"]

        # bob fetch listing to cache
        api_url = bob["gateway_url"] + "ipfs/" + listingId
        requests.get(api_url)

        # shutdown alice
        api_url = alice["gateway_url"] + "ob/shutdown"
        requests.post(api_url, data="")
        time.sleep(4)

        # bob send order
        with open('testdata/'+ self.buyer_version +'/order_direct.json') as order_file:
            order_json = json.load(order_file, object_pairs_hook=OrderedDict)
        order_json["items"][0]["listingHash"] = listingId
        order_json["moderator"] = moderatorId
        order_json["paymentCoin"] = "t" + self.cointype
        api_url = bob["gateway_url"] + "ob/purchase"
        r = requests.post(api_url, data=json.dumps(order_json, indent=4))
        if r.status_code == 404:
            raise TestFailure("RejectModeratedOffline - FAIL: Purchase post endpoint not found")
        elif r.status_code != 200:
            resp = json.loads(r.text)
            raise TestFailure("RejectModeratedOffline - FAIL: Purchase POST failed. Reason: %s", resp["reason"])
        resp = json.loads(r.text)
        orderId = resp["orderId"]
        payment_address = resp["paymentAddress"]
        payment_amount = resp["amount"]
        if resp["vendorOnline"] == True:
            raise TestFailure("RejectModeratedOffline - FAIL: Purchase returned vendor is online")

        # check the purchase saved correctly
        api_url = bob["gateway_url"] + "ob/order/" + orderId
        r = requests.get(api_url)
        if r.status_code != 200:
            raise TestFailure("RejectModeratedOffline - FAIL: Couldn't load order from Bob")
        resp = json.loads(r.text)
        if resp["state"] != "AWAITING_PAYMENT":
            raise TestFailure("RejectModeratedOffline - FAIL: Bob purchase saved in incorrect state")
        if resp["funded"] == True:
            raise TestFailure("RejectModeratedOffline - FAIL: Bob incorrectly saved as funded")

        # fund order
        spend = {
            "currencyCode": "T" + self.cointype,
            "address": payment_address,
            "amount": payment_amount["amount"],
            "feeLevel": "NORMAL",
            "requireAssociateOrder": False
        }
        if self.buyer_version == 4:
            spend["amount"] = payment_amount
            spend["wallet"] = "T" + self.cointype

        api_url = bob["gateway_url"] + "wallet/spend"
        r = requests.post(api_url, data=json.dumps(spend, indent=4))
        if r.status_code == 404:
            raise TestFailure("RejectModeratedOffline - FAIL: Spend post endpoint not found")
        elif r.status_code != 200:
            resp = json.loads(r.text)
            raise TestFailure("RejectModeratedOffline - FAIL: Purchase POST failed. Reason: %s", resp["reason"])
        time.sleep(20)

        # check bob detected payment
        api_url = bob["gateway_url"] + "ob/order/" + orderId
        r = requests.get(api_url)
        if r.status_code != 200:
            raise TestFailure("RejectModeratedOffline - FAIL: Couldn't load order from Bob")
        resp = json.loads(r.text)
        if len(resp["paymentAddressTransactions"]) <= 0:
            raise TestFailure("RejectModeratedOffline - FAIL: Bob failed to detect his payment")
        if resp["funded"] == False:
            raise TestFailure("RejectModeratedOffline - FAIL: Bob incorrectly saved as unfunded")
        if resp["state"] != "PENDING":
            raise TestFailure("RejectModeratedOffline - FAIL: Bob purchase saved in incorrect state")

        # generate one more block containing this tx
        self.send_bitcoin_cmd("generate", 1)

        # startup alice again
        self.start_node(1, alice)
        time.sleep(45)

        # alice reject order
        api_url = alice["gateway_url"] + "ob/orderconfirmation"
        oc = {
            "orderId": orderId,
            "reject": True
        }
        r = requests.post(api_url, data=json.dumps(oc, indent=4))
        if r.status_code == 404:
            raise TestFailure("RejectModeratedOffline - FAIL: Order confirmation post endpoint not found")
        elif r.status_code != 200:
            resp = json.loads(r.text)
            raise TestFailure("RejectModeratedOffline - FAIL: OrderConfirmation POST failed. Reason: %s", resp["reason"])
        time.sleep(20)

        # alice check order rejected correctly
        api_url = alice["gateway_url"] + "ob/order/" + orderId
        r = requests.get(api_url)
        if r.status_code != 200:
            raise TestFailure("RejectModeratedOffline - FAIL: Couldn't load order from Alice")
        resp = json.loads(r.text)
        if resp["state"] != "DECLINED":
            raise TestFailure("RejectModeratedOffline - FAIL: Alice failed to save as declined")
        if len(resp["paymentAddressTransactions"]) != 2:
            raise TestFailure("RejectModeratedOffline - FAIL: Alice failed to detect outgoing payment")

        # bob check order rejected correctly
        api_url = bob["gateway_url"] + "ob/order/" + orderId
        r = requests.get(api_url)
        if r.status_code != 200:
            raise TestFailure("RejectModeratedOffline - FAIL: Couldn't load order from Bob")
        resp = json.loads(r.text)
        if resp["state"] != "DECLINED":
            raise TestFailure("RejectModeratedOffline - FAIL: Bob failed to save as declined")
        if len(resp["paymentAddressTransactions"]) != 2:
            raise TestFailure("RejectModeratedOffline - FAIL: Bob failed to detect outgoing payment")

        self.send_bitcoin_cmd("generate", 1)
        time.sleep(2)

        # Check the funds moved into bob's wallet
        api_url = bob["gateway_url"] + "wallet/balance/T" + self.cointype
        r = requests.get(api_url)
        if r.status_code == 200:
            resp = json.loads(r.text)
            confirmed = int(resp["confirmed"])
            amt = 0
            if self.buyer_version == 4:
                amt = payment_amount
            else:
                amt = int(payment_amount["amount"])
            #unconfirmed = int(resp["unconfirmed"])
            if confirmed <= 50 - amt:
                raise TestFailure("RejectModeratedOffline - FAIL: Bob failed to receive the multisig payout")
        else:
            raise TestFailure("RejectModeratedOffline - FAIL: Failed to query Bob's balance")

        print("RejectModeratedOffline - PASS")


if __name__ == '__main__':
    print("Running RejectModeratedOffline")
    RejectModeratedOffline().main(["--regtest", "--disableexchangerates"])
