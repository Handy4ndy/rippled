#include <test/jtx/AMM.h>
#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/TestHelpers.h>
#include <test/jtx/acctdelete.h>
#include <test/jtx/amount.h>
#include <test/jtx/check.h>
#include <test/jtx/delegate.h>
#include <test/jtx/deposit.h>
#include <test/jtx/depositnoauth.h>
#include <test/jtx/escrow.h>
#include <test/jtx/fee.h>
#include <test/jtx/flags.h>
#include <test/jtx/mpt.h>
#include <test/jtx/multisign.h>
#include <test/jtx/offer.h>
#include <test/jtx/pay.h>
#include <test/jtx/paychan.h>
#include <test/jtx/regkey.h>
#include <test/jtx/require.h>
#include <test/jtx/sig.h>
#include <test/jtx/sponsor.h>
#include <test/jtx/tag.h>
#include <test/jtx/ter.h>
#include <test/jtx/ticket.h>
#include <test/jtx/token.h>
#include <test/jtx/trust.h>
#include <test/jtx/txflags.h>
#include <test/jtx/vault.h>
#include <test/jtx/withdrawauth.h>

#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/Issue.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/SeqProxy.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>

#include <chrono>

namespace xrpl::test {

struct PaymentPolicy_test : public beast::unit_test::Suite
{
    void
    testDepositNoauthBlocks()
    {
        testcase("DepositNoauth blocks inbound payment");
        using namespace jtx;
        Account const alice{"alice"};
        Account const bob{"bob"};
        Env env(*this);
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfDepositNoauth));
        env.close();
        env(depositnoauth::unauth(alice, bob));
        env.close();

        BEAST_EXPECT(env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));
        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
    }

    void
    testWithdrawPreauthRequired()
    {
        testcase("WithdrawAuth requires WithdrawPreauth");
        using namespace jtx;
        Account const alice{"alice"};
        Account const bob{"bob"};
        Env env(*this);
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();

        env(withdrawauth::auth(alice, bob));
        env.close();
        env(pay(alice, bob, XRP(1)));
        env.close();
    }

    void
    testWithdrawNoauthBeatsAllow()
    {
        testcase("WithdrawNoauth beats WithdrawPreauth");
        using namespace jtx;
        Account const alice{"alice"};
        Account const bob{"bob"};
        Env env(*this);
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env(fset(alice, asfWithdrawNoauth));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env(withdrawauth::noauth(alice, bob));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecWITHDRAW_NOAUTH));
        env.close();
    }

    void
    testDepositNoauthBeatsDepositAuthAllow()
    {
        testcase("DepositNoauth deny beats DepositPreauth allow");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};

        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfDepositAuth));
        env(fset(alice, asfDepositNoauth));
        env.close();
        env(deposit::auth(alice, bob));
        env.close();
        env(depositnoauth::unauth(alice, bob));
        env.close();

        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
    }

    void
    testWithdrawPreauthDestinationTag()
    {
        testcase("WithdrawPreauth DestinationTag exact match");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};

        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();

        env(withdrawauth::auth(alice, bob, 42));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 42)));
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 99)));

        env(pay(alice, bob, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
        env(pay(alice, bob, XRP(1)), Dtag(99), Ter(tecNO_PERMISSION));
        env.close();
        env(pay(alice, bob, XRP(1)), Dtag(42));
        env.close();

        env(withdrawauth::auth(alice, bob));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
        env(pay(alice, bob, XRP(1)));
        env.close();

        env(withdrawauth::unauth(alice, bob, 42));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 42)));
        env(pay(alice, bob, XRP(1)), Dtag(42), Ter(tecNO_PERMISSION));
        env.close();
        env(pay(alice, bob, XRP(1)));
        env.close();
    }

    void
    testWithdrawNoauthClear()
    {
        testcase("WithdrawNoauth clear restores outbound Payment");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};

        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfWithdrawNoauth));
        env.close();
        env(withdrawauth::noauth(alice, bob));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawNoauth(alice.id(), bob.id())));
        env(pay(alice, bob, XRP(1)), Ter(tecWITHDRAW_NOAUTH));
        env.close();

        env(withdrawauth::clearNoauth(alice, bob));
        env.close();
        env(pay(alice, bob, XRP(1)));
        env.close();
    }

    void
    testFeatureDisabled()
    {
        testcase("PaymentPolicy TTs disabled without feature");
        using namespace jtx;

        Env env(*this, testableAmendments() - featurePaymentPolicy);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(depositnoauth::unauth(alice, bob), Ter(temDISABLED));
        env(withdrawauth::auth(alice, bob), Ter(temDISABLED));
        env(pay(bob, alice, XRP(1)));
        env.close();
    }

    void
    testDepositNoauthExpiration()
    {
        testcase("DepositNoauth lazy expiry allows payment");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfDepositNoauth));
        env.close();

        auto const now = env.now().time_since_epoch().count();
        std::uint32_t const exp = static_cast<std::uint32_t>(now + 3600);
        env(depositnoauth::unauth(alice, bob, exp));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));

        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();

        env.close(std::chrono::seconds(4000));
        env(pay(bob, alice, XRP(1)));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));
    }

    void
    testDepositNoauthCreatePaths()
    {
        testcase("DepositNoauth blocks CheckCreate, PayChanCreate/Fund, EscrowCreate");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfDepositNoauth));
        env(depositnoauth::unauth(alice, bob));
        env.close();

        env(check::create(bob, alice, XRP(5)), Ter(tecDEPOSIT_NOAUTH));
        env(paychan::create(bob, alice, XRP(10), 3600s, bob.pk()), Ter(tecDEPOSIT_NOAUTH));
        env(escrow::create(bob, alice, XRP(10)),
            escrow::kFinishTime(env.now() + 1s),
            Ter(tecDEPOSIT_NOAUTH));
        env.close();
    }

    void
    testWithdrawSetauthInheritance()
    {
        testcase("WithdrawSetauth provider inheritance allow/deny");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const provider{"provider"};
        Account const carol{"carol"};

        env.fund(XRP(10000), alice, bob, provider, carol);
        env.close();

        env(fset(provider, asfWithdrawAuth));
        env(withdrawauth::auth(provider, bob));
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env(withdrawauth::setauth(alice, {provider}, /*noauthList=*/false));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawSetPreauth(alice.id())));

        env(pay(alice, bob, XRP(1)));
        env.close();
        env(pay(alice, carol, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();

        env(fset(provider, asfWithdrawNoauth));
        env(withdrawauth::noauth(provider, bob));
        env.close();
        env(fset(alice, asfWithdrawNoauth));
        env(withdrawauth::setauth(alice, {provider}, /*noauthList=*/true));
        env.close();

        env(withdrawauth::auth(alice, bob));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecWITHDRAW_NOAUTH));
        env.close();
    }

    void
    testSoftOutboundCreatePaths()
    {
        testcase("Soft withdraw binds create/cash/DEX value paths");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};

        env.fund(XRP(10000), alice, bob, carol);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();

        env(escrow::create(alice, carol, XRP(10)),
            escrow::kFinishTime(env.now() + 1s),
            Ter(tecNO_PERMISSION));
        env.close();
        env(escrow::create(alice, bob, XRP(10)), escrow::kFinishTime(env.now() + 1s));
        env.close();

        env(check::create(alice, carol, XRP(5)), Ter(tecNO_PERMISSION));
        env.close();
        auto const bobCheckSeq = env.seq(alice);
        env(check::create(alice, bob, XRP(5)));
        env.close();
        auto const chkId = getCheckIndex(alice.id(), bobCheckSeq);
        env(check::cash(bob, chkId, XRP(5)));
        env.close();

        env(paychan::create(alice, carol, XRP(10), 3600s, alice.pk()), Ter(tecNO_PERMISSION));
        env.close();
        env(paychan::create(alice, bob, XRP(10), 3600s, alice.pk()));
        env.close();

        Account const gw{"gw"};
        env.fund(XRP(10000), gw);
        env.close();
        auto const USD = gw["USD"];
        env(trust(alice, USD(1000)));
        env.close();
        env(pay(gw, alice, USD(100)));
        env.close();
        env(offer(alice, XRP(10), USD(10)), Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        env(fset(alice, asfWithdrawNoauth));
        env.close();
        env(offer(alice, XRP(10), USD(10)), Ter(tecNO_PERMISSION));
        env.close();
        env(fclear(alice, asfWithdrawNoauth));
        env.close();
        env(offer(alice, XRP(10), USD(10)));
        env.close();
    }

    void
    testMptDexRespectsWithdrawAuth()
    {
        testcase("MPT OfferCreate is an uncontrolled exit under WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, gw);
        env.close();

        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(offer(alice, mptA(10), XRP(10)), Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        env(offer(alice, mptA(10), XRP(10)));
        env.close();
    }

    void
    testMptPaymentDestPolicy()
    {
        testcase("MPT Payment honors WithdrawAuth and DepositNoauth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, gw);
        env.close();

        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(pay(alice, bob, mptA(10)), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();
        env(pay(alice, bob, mptA(10)));
        env.close();
        BEAST_EXPECT(mptA.getBalance(bob) == 1010);

        env(fset(bob, asfDepositNoauth));
        env.close();
        env(depositnoauth::unauth(bob, alice));
        env.close();
        env(pay(alice, bob, mptA(10)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
    }

    void
    testMptCheckAndAmmRespectWithdrawAuth()
    {
        testcase("MPT CheckCreate and AMMCreate blocked by WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, bob, gw);
        env.close();

        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 5000});
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(check::create(alice, bob, mptA(50)), Ter(tecNO_PERMISSION));
        env.close();
        AMM(env, alice, XRP(1000), mptA(1000), Ter(tecNO_PERMISSION));

        env(withdrawauth::auth(alice, bob));
        env.close();
        env(check::create(alice, bob, mptA(50)));
        env.close();
    }

    void
    testMptRestingOfferNotCrossed()
    {
        testcase("WithdrawAuth drops resting MPT offers on crossing");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, gw);
        env.close();

        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();

        env(offer(alice, XRP(50), mptA(50)));
        env.close();
        BEAST_EXPECT(mptA.getBalance(alice) == 1000);

        env(fset(alice, asfWithdrawAuth));
        env.close();

        env(offer(bob, mptA(50), XRP(50)));
        env.close();
        BEAST_EXPECT(mptA.getBalance(alice) == 1000);
        BEAST_EXPECT(mptA.getBalance(bob) == 1000);
    }

    void
    testCustomTransactorsMalformed()
    {
        testcase("Policy transactors reject self dest");
        using namespace jtx;

        {
            Env env(*this);
            Account const alice{"alice"};
            Account const bob{"bob"};
            env.fund(XRP(10000), alice, bob);
            env.close();

            env(withdrawauth::auth(alice, alice), Ter(temCANNOT_PREAUTH_SELF));
            env.close();
            env(depositnoauth::unauth(alice, alice), Ter(temCANNOT_NOAUTH_SELF));
            env.close();
            env(withdrawauth::noauth(alice, alice), Ter(temCANNOT_NOAUTH_SELF));
            env.close();
        }
    }

    void
    testWithdrawAuthAccountDelete()
    {
        testcase("WithdrawAuth binds AccountDelete destination");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(10000), alice, bob, carol);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();

        auto const acctDelFee = drops(env.current()->fees().increment);
        incLgrSeqForAccDel(env, alice);
        env(acctdelete(alice, carol), Fee(acctDelFee), Ter(tecNO_PERMISSION));
        env.close();

        env(withdrawauth::auth(alice, carol));
        env.close();
        incLgrSeqForAccDel(env, alice);
        env(acctdelete(alice, carol), Fee(acctDelFee));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::account(alice.id())));
    }

    void
    testPayChanFundUnderWithdrawAuth()
    {
        testcase("PayChanFund honors WithdrawAuth against channel dest");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();

        // Create+fund blocked without dest preauth under WithdrawAuth.
        env(paychan::create(alice, bob, XRP(10), 3600s, alice.pk()), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();

        auto const seq = env.seq(alice);
        env(paychan::create(alice, bob, XRP(10), 3600s, alice.pk()));
        env.close();
        auto const chan = paychan::channel(alice, bob, seq);

        env(withdrawauth::unauth(alice, bob));
        env.close();
        env(paychan::fund(alice.id(), chan, XRP(5)), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();
        env(paychan::fund(alice.id(), chan, XRP(5)));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        env(fset(alice, asfWithdrawNoauth));
        env(withdrawauth::noauth(alice, bob));
        env.close();
        env(paychan::fund(alice.id(), chan, XRP(5)), Ter(tecWITHDRAW_NOAUTH));
        env.close();

        env(fclear(alice, asfWithdrawNoauth));
        env.close();
        env(paychan::fund(alice.id(), chan, XRP(5)));
        env.close();
    }

    void
    testDelegateHonorsOwnerPolicy()
    {
        testcase("Delegate cannot bypass owner's Withdraw/Deposit policy");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        Account const dave{"dave"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, carol, dave, gw);
        env.close();
        auto const USD = gw["USD"];
        env(trust(alice, USD(1000)));
        env.close();
        env(pay(gw, alice, USD(100)));
        env.close();

        env(delegate::set(alice, bob, {"Payment", "CheckCreate", "EscrowCreate", "OfferCreate"}));
        env.close();

        // Owner WithdrawAuth: unlisted dest fails even when the delegate signs.
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(pay(alice, carol, XRP(1)), delegate::As(bob), Ter(tecNO_PERMISSION));
        env.close();
        env(check::create(alice, carol, XRP(5)), delegate::As(bob), Ter(tecNO_PERMISSION));
        env.close();
        env(escrow::create(alice, carol, XRP(10)),
            escrow::kFinishTime(env.now() + 1s),
            delegate::As(bob),
            Ter(tecNO_PERMISSION));
        env.close();
        env(offer(alice, XRP(10), USD(10)), delegate::As(bob), Ter(tecNO_PERMISSION));
        env.close();

        // Delegate's own WithdrawAuth must not be the gate on alice's funds.
        env(fset(bob, asfWithdrawAuth));
        env.close();
        env(withdrawauth::auth(alice, carol));
        env.close();
        env(pay(alice, carol, XRP(1)), delegate::As(bob));
        env.close();
        env(check::create(alice, carol, XRP(5)), delegate::As(bob));
        env.close();

        // Owner deny list still wins.
        env(fset(alice, asfWithdrawNoauth));
        env(withdrawauth::noauth(alice, carol));
        env.close();
        env(pay(alice, carol, XRP(1)), delegate::As(bob), Ter(tecWITHDRAW_NOAUTH));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env(fclear(alice, asfWithdrawNoauth));
        env.close();

        // Inbound: dest denied the owner, not the delegate.
        env(fset(dave, asfDepositNoauth));
        env(depositnoauth::unauth(dave, alice));
        env.close();
        env(pay(alice, dave, XRP(1)), delegate::As(bob), Ter(tecDEPOSIT_NOAUTH));
        env.close();
        env(check::create(alice, dave, XRP(5)), delegate::As(bob), Ter(tecDEPOSIT_NOAUTH));
        env.close();

        // Dest DepositAuth without preauth of the owner (not the delegate).
        env(fset(carol, asfDepositAuth));
        env.close();
        env(pay(alice, carol, XRP(1)), delegate::As(bob), Ter(tecNO_PERMISSION));
        env.close();
    }

    void
    testSoftBurnNeedsWithdrawAuth()
    {
        testcase("Soft PP: self-burn blocked by WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        env.fund(XRP(10000), alice);
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        auto const nftId = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        env(token::burn(alice, nftId), Ter(tecNO_PERMISSION));
        env.close();
    }

    void
    testNftSoftWithdrawAuth()
    {
        testcase("Soft PP: NFT mint/create/accept honor WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(10000), alice, bob, carol);
        env.close();

        // Mint with open-sell Amount is a U-exit under WithdrawAuth.
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(token::mint(alice, 0),
            Txflags(tfTransferable),
            token::Amount(drops(1)),
            Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        auto const nftSell = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        auto const nftBuy = token::getNextID(env, bob, 0, tfTransferable);
        env(token::mint(bob, 0), Txflags(tfTransferable));
        env.close();
        auto const nftAcceptBuy = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        auto const nftAcceptSell = token::getNextID(env, bob, 0, tfTransferable);
        env(token::mint(bob, 0), Txflags(tfTransferable));
        env.close();

        // Open sell create is a U-exit.
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(token::createOffer(alice, nftSell, drops(1)),
            Txflags(tfSellNFToken),
            Ter(tecNO_PERMISSION));
        env.close();

        // Directed sell needs WithdrawPreauth of Destination (NFT leave gate).
        env(token::createOffer(alice, nftSell, drops(1)),
            Txflags(tfSellNFToken),
            token::Destination(bob),
            Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();
        env(token::createOffer(alice, nftSell, drops(1)),
            Txflags(tfSellNFToken),
            token::Destination(bob));
        env.close();

        // Directed buy create needs WithdrawPreauth of Destination.
        env(token::createOffer(alice, nftBuy, drops(1)),
            token::Owner(bob),
            token::Destination(carol),
            Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, carol));
        env.close();
        env(token::createOffer(alice, nftBuy, drops(1)),
            token::Owner(bob),
            token::Destination(carol));
        env.close();

        // Accept buy: pay() withdraw-checks the buyer (bob) → seller (alice).
        env(fclear(alice, asfWithdrawAuth));
        env.close();
        auto const buyOffer = keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
        env(token::createOffer(bob, nftAcceptBuy, drops(1)), token::Owner(alice));
        env.close();
        env(fset(bob, asfWithdrawAuth));
        env.close();
        env(token::acceptBuyOffer(alice, buyOffer), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(bob, alice));
        env.close();
        env(token::acceptBuyOffer(alice, buyOffer));
        env.close();

        // Accept sell: pay() withdraw-checks the buyer (alice) → seller (bob).
        env(fclear(bob, asfWithdrawAuth));
        env.close();
        // Drop alice→bob preauth left from directed-sell setup above.
        env(withdrawauth::unauth(alice, bob));
        env.close();
        auto const sellOffer = keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
        env(token::createOffer(bob, nftAcceptSell, drops(1)), Txflags(tfSellNFToken));
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(token::acceptSellOffer(alice, sellOffer), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();
        env(token::acceptSellOffer(alice, sellOffer));
        env.close();
    }

    void
    testCheckCashDestinationTag()
    {
        testcase("Soft PP: CheckCash uses check DestinationTag for WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        std::uint32_t const tag = 42;
        env(withdrawauth::auth(alice, bob, tag));
        env.close();

        env(check::create(alice, bob, XRP(5)), DestTag(99), Ter(tecNO_PERMISSION));
        env.close();

        auto const checkSeq = env.seq(alice);
        env(check::create(alice, bob, XRP(5)), DestTag(tag));
        env.close();
        auto const checkId = getCheckIndex(alice.id(), checkSeq);
        // Casher is bob; soft subject is alice (creator). Tag must match.
        env(check::cash(bob, checkId, XRP(5)));
        env.close();
    }

    void
    testEscrowFinishOwnerWithdrawAuth()
    {
        testcase("Soft PP: EscrowFinish binds owner WithdrawAuth to dest");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(10000), alice, bob, carol);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();

        auto const seqOk = env.seq(alice);
        env(escrow::create(alice, bob, XRP(5)), escrow::kFinishTime(env.now() + 1s));
        env.close();

        // Create to non-preauth dest fails; finish path is exercised below.
        env(escrow::create(alice, carol, XRP(5)),
            escrow::kFinishTime(env.now() + 1s),
            Ter(tecNO_PERMISSION));
        env.close();

        env.close(std::chrono::seconds(2));
        // Third party finishes; withdraw subject remains escrow owner alice.
        env(escrow::finish(carol, alice, seqOk));
        env.close();

        // Create while allow-mode is off, then re-arm WithdrawAuth without dest preauth.
        env(fclear(alice, asfWithdrawAuth));
        env.close();
        auto const seqBad = env.seq(alice);
        env(escrow::create(alice, carol, XRP(5)), escrow::kFinishTime(env.now() + 1s));
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env.close(std::chrono::seconds(2));
        env(escrow::finish(carol, alice, seqBad), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, carol));
        env.close();
        env(escrow::finish(carol, alice, seqBad));
        env.close();
    }

    void
    testPayChanClaimBalanceWithdrawAuth()
    {
        testcase("Soft PP: PayChanClaim with Balance honors owner WithdrawAuth");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(10000), alice, bob, carol);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();

        auto const seqBob = env.seq(alice);
        env(paychan::create(alice, bob, XRP(10), 3600s, alice.pk()));
        env.close();
        auto const chanBob = paychan::channel(alice, bob, seqBob);
        env(paychan::claim(alice.id(), chanBob, XRP(1), XRP(1)));
        env.close();
        BEAST_EXPECT(paychan::channelBalance(*env.closed(), chanBob) == XRP(1));

        // Channel to non-preauth dest needs auth first.
        env(paychan::create(alice, carol, XRP(10), 3600s, alice.pk()), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, carol));
        env.close();
        auto const seqCarol = env.seq(alice);
        env(paychan::create(alice, carol, XRP(10), 3600s, alice.pk()));
        env.close();
        auto const chanCarol = paychan::channel(alice, carol, seqCarol);

        env(withdrawauth::unauth(alice, carol));
        env.close();
        env(paychan::claim(alice.id(), chanCarol, XRP(1), XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, carol));
        env.close();
        env(paychan::claim(alice.id(), chanCarol, XRP(1), XRP(1)));
        env.close();
    }

    void
    testVaultDepositWithdrawAuth()
    {
        testcase("Soft PP: VaultDeposit is U-exit under WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const owner{"owner"};
        Account const alice{"alice"};
        env.fund(XRP(10000), owner, alice);
        env.close();

        Vault vault{env};
        auto [tx, keylet] = vault.create({.owner = owner, .asset = xrpIssue()});
        env(tx);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(vault.deposit({.depositor = alice, .id = keylet.key, .amount = XRP(10)}),
            Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        env(vault.deposit({.depositor = alice, .id = keylet.key, .amount = XRP(10)}));
        env.close();
    }

    void
    testVaultWithdrawDestPolicy()
    {
        testcase("Soft PP: VaultWithdraw to non-preauth dest under WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const owner{"owner"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(10000), owner, alice, bob, carol);
        env.close();

        Vault vault{env};
        auto [tx, keylet] = vault.create({.owner = owner, .asset = xrpIssue()});
        env(tx);
        env.close();
        env(vault.deposit({.depositor = alice, .id = keylet.key, .amount = XRP(100)}));
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();

        // Self withdraw is a U-exit under WithdrawAuth.
        env(vault.withdraw({.depositor = alice, .id = keylet.key, .amount = XRP(10)}),
            Ter(tecNO_PERMISSION));
        env.close();

        auto wBad = vault.withdraw({.depositor = alice, .id = keylet.key, .amount = XRP(10)});
        wBad[sfDestination] = carol.human();
        env(wBad, Ter(tecNO_PERMISSION));
        env.close();

        auto wOk = vault.withdraw({.depositor = alice, .id = keylet.key, .amount = XRP(10)});
        wOk[sfDestination] = bob.human();
        env(wOk);
        env.close();

        // Tag-scoped preauth: tag 0 allow must not satisfy DestinationTag 7.
        env(withdrawauth::unauth(alice, bob));
        env.close();
        env(withdrawauth::auth(alice, bob, 7));
        env.close();
        auto wTag0 = vault.withdraw({.depositor = alice, .id = keylet.key, .amount = XRP(10)});
        wTag0[sfDestination] = bob.human();
        env(wTag0, Ter(tecNO_PERMISSION));
        env.close();
        auto wTag7 = vault.withdraw({.depositor = alice, .id = keylet.key, .amount = XRP(10)});
        wTag7[sfDestination] = bob.human();
        wTag7[sfDestinationTag] = 7;
        env(wTag7);
        env.close();
    }

    void
    testAmmDepositBidWithdrawAuth()
    {
        testcase("Soft PP: AMMDeposit/Withdraw/Bid blocked by WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, gw);
        env.close();
        auto const USD = gw["USD"];
        env(trust(alice, USD(100000)));
        env.close();
        env(pay(gw, alice, USD(10000)));
        env.close();

        // Create AMM while allow-mode is off, then re-arm WithdrawAuth.
        AMM amm(env, alice, XRP(1000), USD(1000));
        env(fset(alice, asfWithdrawAuth));
        env.close();

        amm.deposit(alice, XRP(100), USD(100), std::nullopt, std::nullopt, Ter(tecNO_PERMISSION));
        env(amm.bid({.account = alice, .bidMin = 100}), Ter(tecNO_PERMISSION));
        amm.withdraw(alice, XRP(10), std::nullopt, std::nullopt, Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        amm.deposit(alice, XRP(100), USD(100));
        env.close();
        env(amm.bid({.account = alice, .bidMin = 100}));
        env.close();
        amm.withdraw(alice, XRP(10));
        env.close();
    }

    void
    testSponsorshipSetWithdrawAuth()
    {
        testcase("Soft PP: SponsorshipSet create/grow blocked by WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(100000), alice, bob);
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(sponsor::set(alice, 0, 100, XRP(1000)),
            sponsor::SponseeAcc(bob),
            Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        env(sponsor::set(alice, 0, 100, XRP(1000)), sponsor::SponseeAcc(bob));
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(sponsor::set_fee(alice, 0, XRP(50)), sponsor::SponseeAcc(bob), Ter(tecNO_PERMISSION));
        env.close();
    }

    void
    testSponsorshipTransferWithdrawAuth()
    {
        testcase("Soft PP: SponsorshipTransfer create blocked for WithdrawAuth sponsor");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const sponsor{"sponsor"};
        env.fund(XRP(100000), alice, sponsor);
        env.close();

        env(fset(sponsor, asfWithdrawAuth));
        env.close();
        env(sponsor::transfer(alice, tfSponsorshipCreate),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(sponsor, asfWithdrawAuth));
        env.close();
        env(sponsor::transfer(alice, tfSponsorshipCreate),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor));
        env.close();
    }

    void
    testReserveSponsorWithdrawAuth()
    {
        testcase("Soft PP: reserve sponsor TrustSet is U-exit under WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const sponsor{"sponsor"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, sponsor, gw);
        env.close();
        auto const USD = gw["USD"];

        // TrustSet is on the v1 reserve-sponsor allow-list; OfferCreate is not.
        env(fset(sponsor, asfWithdrawAuth));
        env.close();
        env(trust(alice, USD(1000)),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(sponsor, asfWithdrawAuth));
        env.close();
        env(trust(alice, USD(1000)),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor));
        env.close();
    }

    void
    testConfidentialMptConvertWithdrawAuth()
    {
        testcase("Soft PP: ConfidentialMPT Convert/ConvertBack/Send/MergeInbox under WithdrawAuth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({
            .ownerCount = 1,
            .flags = tfMPTCanTransfer | tfMPTCanLock | tfMPTCanHoldConfidentialBalance,
        });
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 100);
        mpt.pay(alice, carol, 100);
        mpt.generateKeyPair(alice);
        mpt.set({.account = alice, .issuerPubKey = mpt.getPubKey(alice)});
        mpt.generateKeyPair(bob);
        mpt.generateKeyPair(carol);

        // Register holder keys; fund bob's confidential spending for ConvertBack/Send.
        mpt.convert({
            .account = bob,
            .amt = 0,
            .holderPubKey = mpt.getPubKey(bob),
        });
        mpt.convert({
            .account = carol,
            .amt = 0,
            .holderPubKey = mpt.getPubKey(carol),
        });
        env.close();
        env(fset(bob, asfWithdrawAuth));
        env.close();
        mpt.convert({
            .account = bob,
            .amt = 20,
            .err = tecNO_PERMISSION,
        });
        env.close();

        env(fclear(bob, asfWithdrawAuth));
        env.close();
        mpt.convert({.account = bob, .amt = 20});
        env.close();
        // Convert credits the inbox; spending (ConvertBack/Send) needs a merge.
        mpt.mergeInbox({.account = bob});
        env.close();

        // ConvertBack U-exit: deny under WithdrawAuth, success after fclear.
        env(fset(bob, asfWithdrawAuth));
        env.close();
        mpt.convertBack({
            .account = bob,
            .amt = 10,
            .err = tecNO_PERMISSION,
        });
        env.close();
        env(fclear(bob, asfWithdrawAuth));
        env.close();
        mpt.convertBack({.account = bob, .amt = 10});
        env.close();

        // Send U-exit: deny under WithdrawAuth, success after fclear.
        env(fset(bob, asfWithdrawAuth));
        env.close();
        mpt.send({
            .account = bob,
            .dest = carol,
            .amt = 5,
            .err = tecNO_PERMISSION,
        });
        env.close();
        env(fclear(bob, asfWithdrawAuth));
        env.close();
        mpt.send({.account = bob, .dest = carol, .amt = 5});
        env.close();

        // MergeInbox U-exit: empty-inbox deny under WithdrawAuth, then success.
        env(fset(bob, asfWithdrawAuth));
        env.close();
        mpt.mergeInbox({.account = bob, .err = tecNO_PERMISSION});
        env.close();
        env(fclear(bob, asfWithdrawAuth));
        env.close();
        mpt.mergeInbox({.account = bob});
        env.close();
    }

    void
    run() override
    {
        testDepositNoauthBlocks();
        testWithdrawPreauthRequired();
        testWithdrawNoauthBeatsAllow();
        testDepositNoauthBeatsDepositAuthAllow();
        testWithdrawPreauthDestinationTag();
        testWithdrawNoauthClear();
        testFeatureDisabled();
        testDepositNoauthExpiration();
        testDepositNoauthCreatePaths();
        testWithdrawSetauthInheritance();
        testSoftOutboundCreatePaths();
        testMptDexRespectsWithdrawAuth();
        testMptPaymentDestPolicy();
        testMptCheckAndAmmRespectWithdrawAuth();
        testMptRestingOfferNotCrossed();
        testCustomTransactorsMalformed();
        testWithdrawAuthAccountDelete();
        testPayChanFundUnderWithdrawAuth();
        testDelegateHonorsOwnerPolicy();
        testSoftBurnNeedsWithdrawAuth();
        testNftSoftWithdrawAuth();
        testCheckCashDestinationTag();
        testEscrowFinishOwnerWithdrawAuth();
        testPayChanClaimBalanceWithdrawAuth();
        testVaultDepositWithdrawAuth();
        testVaultWithdrawDestPolicy();
        testAmmDepositBidWithdrawAuth();
        testSponsorshipSetWithdrawAuth();
        testSponsorshipTransferWithdrawAuth();
        testReserveSponsorWithdrawAuth();
        testConfidentialMptConvertWithdrawAuth();
    }
};

BEAST_DEFINE_TESTSUITE(PaymentPolicy, app, xrpl);

}  // namespace xrpl::test
