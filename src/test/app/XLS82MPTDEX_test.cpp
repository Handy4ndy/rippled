#include <test/jtx/AMM.h>
#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/TestHelpers.h>
#include <test/jtx/amount.h>
#include <test/jtx/check.h>
#include <test/jtx/mpt.h>
#include <test/jtx/offer.h>
#include <test/jtx/pay.h>
#include <test/jtx/ter.h>
#include <test/jtx/trust.h>

#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>

namespace xrpl::test {

struct XLS82MPTDEX_test : public beast::unit_test::Suite
{
    void
    testAmmCreatePairs()
    {
        testcase("XLS-82 AMMCreate XRP/MPT IOU/MPT MPT/MPT");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, gw);
        env.close();

        auto const USD = gw["USD"];
        env(trust(alice, USD(100000)));
        env.close();
        env(pay(gw, alice, USD(20000)));
        env.close();

        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice}, .pay = 20000});
        MPTTester mptB({.env = env, .issuer = gw, .holders = {alice}, .pay = 20000});
        env.close();

        AMM const ammXrp(env, alice, XRP(1000), mptA(1000));
        BEAST_EXPECT(env.le(keylet::amm(xrpIssue(), mptA)));

        AMM const ammIou(env, alice, USD(1000), mptA(1000));
        AMM const ammMpt(env, alice, mptA(1000), mptB(1000));
        (void)ammIou;
        (void)ammMpt;
    }

    void
    testAmmCreateRequiresCanTrade()
    {
        testcase("XLS-82 AMMCreate fails without lsfMPTCanTrade");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, gw);
        env.close();

        MPTTester mptA(
            {.env = env,
             .issuer = gw,
             .holders = {alice},
             .pay = 20000,
             .flags = tfMPTCanTransfer});
        env.close();

        AMM(env, alice, XRP(1000), mptA(1000), Ter(tecNO_PERMISSION));
    }

    void
    testOfferMptMptAndCanTrade()
    {
        testcase("XLS-82 OfferCreate MPT/MPT and CanTrade gate");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, gw);
        env.close();

        MPTTester tradeable({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        MPTTester locked(
            {.env = env,
             .issuer = gw,
             .holders = {alice, bob},
             .pay = 1000,
             .flags = tfMPTCanTransfer});
        env.close();

        env(offer(alice, tradeable(10), XRP(10)));
        env.close();
        env(offer(bob, XRP(10), tradeable(10)));
        env.close();

        env(offer(alice, locked(10), XRP(10)), Ter(tecNO_PERMISSION));
        env.close();
    }

    void
    testCheckAndPaymentMpt()
    {
        testcase("XLS-82 CheckCreate and Payment with MPT");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, gw);
        env.close();

        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();

        auto const seq = env.seq(alice);
        env(check::create(alice, bob, mptA(50)));
        env.close();
        env(check::cash(bob, getCheckIndex(alice.id(), seq), mptA(50)));
        env.close();

        env(pay(alice, bob, mptA(10)));
        env.close();
    }

    void
    testDisabledWithoutV2()
    {
        testcase("XLS-82 MPT DEX TTs temDISABLED without MPTokensV2");
        using namespace jtx;

        Env env(*this, testableAmendments() - featureMPTokensV2);
        Account const alice{"alice"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, gw);
        env.close();

        MPTTester mptA(
            {.env = env, .issuer = gw, .holders = {alice}, .pay = 1000, .flags = tfMPTCanTransfer});
        env.close();

        env(offer(alice, mptA(10), XRP(10)), Ter(temDISABLED));
        env(check::create(alice, gw, mptA(10)), Ter(temDISABLED));
    }

    void
    run() override
    {
        testAmmCreatePairs();
        testAmmCreateRequiresCanTrade();
        testOfferMptMptAndCanTrade();
        testCheckAndPaymentMpt();
        testDisabledWithoutV2();
    }
};

BEAST_DEFINE_TESTSUITE(XLS82MPTDEX, app, xrpl);

}  // namespace xrpl::test
