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
#include <test/jtx/tag.h>
#include <test/jtx/ter.h>
#include <test/jtx/ticket.h>
#include <test/jtx/trust.h>
#include <test/jtx/withdrawauth.h>

#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
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
        env(withdrawauth::auth(alice, bob));
        env.close();

        auto const seq = env.seq(alice);
        env(paychan::create(alice, bob, XRP(10), 3600s, alice.pk()));
        env.close();
        auto const chan = paychan::channel(alice, bob, seq);

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
    }
};

BEAST_DEFINE_TESTSUITE(PaymentPolicy, app, xrpl);

}  // namespace xrpl::test
