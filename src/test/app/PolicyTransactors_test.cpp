#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/TestHelpers.h>
#include <test/jtx/amount.h>
#include <test/jtx/check.h>
#include <test/jtx/deposit.h>
#include <test/jtx/depositnoauth.h>
#include <test/jtx/depositsetauth.h>
#include <test/jtx/escrow.h>
#include <test/jtx/fee.h>
#include <test/jtx/firewall.h>
#include <test/jtx/flags.h>
#include <test/jtx/pay.h>
#include <test/jtx/paychan.h>
#include <test/jtx/sig.h>
#include <test/jtx/tag.h>
#include <test/jtx/ter.h>
#include <test/jtx/withdrawauth.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/json/json_value.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <chrono>

namespace xrpl::test {

namespace {

Keylet
fwKey(jtx::Account const& owner)
{
    return keylet::firewall(owner.id());
}

void
armFirewall(
    jtx::Env& env,
    jtx::Account const& owner,
    jtx::Account const& cp,
    jtx::Account const& backup,
    std::uint64_t maxFeeDrops = 100000,
    std::optional<std::uint64_t> maxAmountDrops = std::nullopt)
{
    using namespace jtx;
    env(fset(owner, asfWithdrawAuth));
    env.close();
    env(firewall::setCreate(owner, cp, backup, maxFeeDrops, std::nullopt, maxAmountDrops));
    env.close();
}

}  // namespace

struct DepositNoauth_test : public beast::unit_test::Suite
{
    void
    testDisabled()
    {
        testcase("temDISABLED without PaymentPolicy");
        using namespace jtx;
        Env env(*this, testableAmendments() - featurePaymentPolicy);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();
        env(depositnoauth::unauth(alice, bob), Ter(temDISABLED));
    }

    void
    testMalformed()
    {
        testcase("malformed: both/neither fields; cannot noauth self");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();
        {
            json::Value jv;
            jv[jss::Account] = alice.human();
            jv[jss::TransactionType] = jss::DepositNoauth;
            env(jv, Ter(temMALFORMED));
        }
        env(depositnoauth::unauth(alice, alice), Ter(temCANNOT_NOAUTH_SELF));
        env.close();
    }

    void
    testAddBlocksThenRemove()
    {
        testcase("Unauthorize inserts SLE; inbound Payment tecDEPOSIT_NOAUTH; Authorize removes");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();
        env(fset(alice, asfDepositNoauth));
        env.close();
        env(pay(bob, alice, XRP(1)));
        env.close();
        env(depositnoauth::unauth(alice, bob));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));
        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
        env(depositnoauth::auth(alice, bob));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));
        env(pay(bob, alice, XRP(1)));
        env.close();
    }

    void
    testDenyBeatsPreauth()
    {
        testcase("DepositNoauth beats DepositPreauth");
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
        env(depositnoauth::unauth(alice, bob));
        env.close();
        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
    }

    void
    testExpiration()
    {
        testcase("lazy expiry drops SLE and allows payment");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();
        env(fset(alice, asfDepositNoauth));
        env.close();
        auto const now = env.now().time_since_epoch().count();
        env(depositnoauth::unauth(alice, bob, static_cast<std::uint32_t>(now + 3600)));
        env.close();
        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
        env.close(std::chrono::seconds(4000));
        env(pay(bob, alice, XRP(1)));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));
    }

    void
    testBlocksCheckPayChanEscrowCreate()
    {
        testcase(
            "DepositNoauth blocks CheckCreate, PayChanCreate, EscrowCreate; DepositAuth does not");
        using namespace jtx;
        using namespace std::chrono_literals;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        env.fund(XRP(10000), alice, bob, carol);
        env.close();

        // Classic DepositAuth: dest has not preauthorized bob, but create of
        // Check / PayChan / Escrow must still succeed (stock unwedge at cash).
        env(fset(alice, asfDepositAuth));
        env.close();
        env(check::create(bob, alice, XRP(5)));
        env.close();
        auto const bobChanSeq = env.seq(bob);
        env(paychan::create(bob, alice, XRP(10), 3600s, bob.pk()));
        env(escrow::create(bob, alice, XRP(10)), escrow::kFinishTime(env.now() + 1s));
        env.close();
        auto const chan = paychan::channel(bob, alice, bobChanSeq);

        env(fset(alice, asfDepositNoauth));
        env(depositnoauth::unauth(alice, bob));
        env.close();
        env(check::create(bob, alice, XRP(5)), Ter(tecDEPOSIT_NOAUTH));
        env(paychan::create(bob, alice, XRP(10), 3600s, bob.pk()), Ter(tecDEPOSIT_NOAUTH));
        env(escrow::create(bob, alice, XRP(10)),
            escrow::kFinishTime(env.now() + 1s),
            Ter(tecDEPOSIT_NOAUTH));
        env(paychan::fund(bob.id(), chan, XRP(5)), Ter(tecDEPOSIT_NOAUTH));
        env.close();

        env(check::create(carol, alice, XRP(5)));
        env(paychan::create(carol, alice, XRP(10), 3600s, carol.pk()));
        env(escrow::create(carol, alice, XRP(10)), escrow::kFinishTime(env.now() + 1s));
        env.close();
    }

    void
    testFirewalledNeedsCp()
    {
        testcase("while Firewall exists, DepositNoauth needs CounterpartySignature");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        armFirewall(env, alice, cp, backup);
        env(depositnoauth::unauth(alice, bob), Ter(tecREQUIRES_COUNTERPARTY));
        env(depositnoauth::unauth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));
    }

    void
    run() override
    {
        testDisabled();
        testMalformed();
        testAddBlocksThenRemove();
        testDenyBeatsPreauth();
        testExpiration();
        testBlocksCheckPayChanEscrowCreate();
        testFirewalledNeedsCp();
    }
};

struct DepositSetauth_test : public beast::unit_test::Suite
{
    void
    testDisabled()
    {
        testcase("temDISABLED without PaymentPolicy");
        using namespace jtx;
        Env env(*this, testableAmendments() - featurePaymentPolicy);
        Account const alice{"alice"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, provider);
        env.close();
        env(depositsetauth::setauth(alice, {provider}, true), Ter(temDISABLED));
    }

    void
    testFlags()
    {
        testcase("exactly one of tfSetNoauthList / tfSetPreauthList");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, provider);
        env.close();
        {
            json::Value jv = depositsetauth::setauth(alice, {provider}, true);
            jv[jss::Flags] = 0;
            env(jv, Ter(temINVALID_FLAG));
        }
        {
            json::Value jv = depositsetauth::setauth(alice, {provider}, true);
            jv[jss::Flags] = 0x00010000u | 0x00020000u;
            env(jv, Ter(temINVALID_FLAG));
        }
        env.close();
    }

    void
    testSelfProvider()
    {
        testcase("cannot subscribe to self");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        env.fund(XRP(10000), alice);
        env.close();
        env(depositsetauth::setauth(alice, {alice}, true), Ter(temCANNOT_NOAUTH_SELF));
        env.close();
    }

    void
    testNoauthInheritance()
    {
        testcase("tfSetNoauthList inherits provider DepositNoauth");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, bob, provider);
        env.close();
        env(fset(provider, asfDepositNoauth));
        env(depositnoauth::unauth(provider, bob));
        env.close();
        env(fset(alice, asfDepositNoauth));
        env.close();
        env(pay(bob, alice, XRP(1)));
        env.close();
        env(depositsetauth::setauth(alice, {provider}, /*noauthList=*/true));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositSetNoauth(alice.id())));
        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
        env(depositsetauth::clear(alice, true));
        env.close();
        env(pay(bob, alice, XRP(1)));
        env.close();
    }

    void
    testPreauthInheritance()
    {
        testcase("tfSetPreauthList inherits provider DepositPreauth");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, bob, provider);
        env.close();
        env(fset(provider, asfDepositAuth));
        env(deposit::auth(provider, bob));
        env.close();
        env(fset(alice, asfDepositAuth));
        env.close();
        env(pay(bob, alice, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
        env(depositsetauth::setauth(alice, {provider}, /*noauthList=*/false));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositSetPreauth(alice.id())));
        env(pay(bob, alice, XRP(1)));
        env.close();
    }

    void
    testFirewalledNeedsCp()
    {
        testcase("while Firewall exists, DepositSetauth needs CounterpartySignature");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const provider{"provider"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, provider, cp, backup);
        env.close();
        armFirewall(env, alice, cp, backup);
        env(depositsetauth::setauth(alice, {provider}, true), Ter(tecREQUIRES_COUNTERPARTY));
        env(depositsetauth::setauth(alice, {provider}, true), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositSetNoauth(alice.id())));
    }

    void
    run() override
    {
        testDisabled();
        testFlags();
        testSelfProvider();
        testNoauthInheritance();
        testPreauthInheritance();
        testFirewalledNeedsCp();
    }
};

struct WithdrawPreauth_test : public beast::unit_test::Suite
{
    void
    testDisabled()
    {
        testcase("temDISABLED without PaymentPolicy");
        using namespace jtx;
        Env env(*this, testableAmendments() - featurePaymentPolicy);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();
        env(withdrawauth::auth(alice, bob), Ter(temDISABLED));
    }

    void
    testMalformed()
    {
        testcase("cannot preauth self; missing Authorize/Unauthorize");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        env.fund(XRP(10000), alice);
        env.close();
        env(withdrawauth::auth(alice, alice), Ter(temCANNOT_PREAUTH_SELF));
        {
            json::Value jv;
            jv[jss::Account] = alice.human();
            jv[jss::TransactionType] = jss::WithdrawPreauth;
            env(jv, Ter(temMALFORMED));
        }
        env.close();
    }

    void
    testRequiredForWithdrawAuth()
    {
        testcase("asfWithdrawAuth: unlisted dest tecNO_PERMISSION; SLE allows Payment");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
        env(pay(alice, bob, XRP(1)));
        env.close();
        env(withdrawauth::unauth(alice, bob));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
    }

    void
    testDestinationTag()
    {
        testcase("DestinationTag is an exact-match slot (0 = untagged)");
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
        env(pay(alice, bob, XRP(1)), Ter(tecNO_PERMISSION));
        env(pay(alice, bob, XRP(1)), Dtag(99), Ter(tecNO_PERMISSION));
        env(pay(alice, bob, XRP(1)), Dtag(42));
        env.close();
        env(withdrawauth::unauth(alice, bob, 42));
        env.close();
        env(pay(alice, bob, XRP(1)), Dtag(42), Ter(tecNO_PERMISSION));
        env.close();
    }

    void
    testFirewalledNeedsCp()
    {
        testcase("while Firewall exists, WithdrawPreauth needs CounterpartySignature");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        armFirewall(env, alice, cp, backup);
        env(withdrawauth::auth(alice, bob), Ter(tecREQUIRES_COUNTERPARTY));
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
        env(pay(alice, bob, XRP(1)));
        env.close();
    }

    void
    run() override
    {
        testDisabled();
        testMalformed();
        testRequiredForWithdrawAuth();
        testDestinationTag();
        testFirewalledNeedsCp();
    }
};

struct WithdrawNoauth_test : public beast::unit_test::Suite
{
    void
    testDisabled()
    {
        testcase("temDISABLED without PaymentPolicy");
        using namespace jtx;
        Env env(*this, testableAmendments() - featurePaymentPolicy);
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, bob);
        env.close();
        env(withdrawauth::noauth(alice, bob), Ter(temDISABLED));
    }

    void
    testMalformed()
    {
        testcase("cannot noauth self");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        env.fund(XRP(10000), alice);
        env.close();
        env(withdrawauth::noauth(alice, alice), Ter(temCANNOT_NOAUTH_SELF));
        env.close();
    }

    void
    testAddBlocksThenClear()
    {
        testcase("Unauthorize inserts SLE; Payment tecWITHDRAW_NOAUTH; Authorize clears");
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
    testBeatsAllow()
    {
        testcase("deny beats WithdrawPreauth");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
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
    testFirewalledNeedsCp()
    {
        testcase("while Firewall exists, WithdrawNoauth needs CP; deny is tecFIREWALL_BLOCK");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        armFirewall(env, alice, cp, backup, 1'000'000);
        env(fset(alice, asfWithdrawNoauth), Sig(sfCounterpartySignature, cp));
        env.close();
        env(withdrawauth::noauth(alice, bob), Ter(tecREQUIRES_COUNTERPARTY));
        env(withdrawauth::noauth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecFIREWALL_BLOCK));
        env(pay(alice, bob, XRP(1)), Sig(sfCounterpartySignature, cp), Ter(tecFIREWALL_BLOCK));
        env.close();
    }

    void
    run() override
    {
        testDisabled();
        testMalformed();
        testAddBlocksThenClear();
        testBeatsAllow();
        testFirewalledNeedsCp();
    }
};

struct WithdrawSetauth_test : public beast::unit_test::Suite
{
    void
    testDisabled()
    {
        testcase("temDISABLED without PaymentPolicy");
        using namespace jtx;
        Env env(*this, testableAmendments() - featurePaymentPolicy);
        Account const alice{"alice"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, provider);
        env.close();
        env(withdrawauth::setauth(alice, {provider}, false), Ter(temDISABLED));
    }

    void
    testAllowInheritance()
    {
        testcase("tfSetPreauthList inherits provider WithdrawPreauth");
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
        env(pay(alice, carol, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::clearSetauth(alice, false));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
    }

    void
    testDenyInheritance()
    {
        testcase("tfSetNoauthList inherits provider WithdrawNoauth (beats own preauth)");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, bob, provider);
        env.close();
        env(fset(provider, asfWithdrawNoauth));
        env(withdrawauth::noauth(provider, bob));
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env(fset(alice, asfWithdrawNoauth));
        env(withdrawauth::auth(alice, bob));
        env(withdrawauth::setauth(alice, {provider}, /*noauthList=*/true));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawSetNoauth(alice.id())));
        env(pay(alice, bob, XRP(1)), Ter(tecWITHDRAW_NOAUTH));
        env.close();
    }

    void
    run() override
    {
        testDisabled();
        testAllowInheritance();
        testDenyInheritance();
    }
};

struct FirewallSet_test : public beast::unit_test::Suite
{
    static Keylet
    fwKey(jtx::Account const& owner)
    {
        return keylet::firewall(owner.id());
    }

    void
    testDisabled()
    {
        testcase("temDISABLED without Firewall amendment");
        using namespace jtx;
        Env env(*this, testableAmendments() - featureFirewall);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000), Ter(temDISABLED));
    }

    void
    testCreateRequiresFlagAndFields()
    {
        testcase(
            "create: asfWithdrawAuth, Counterparty, Backup, MaxFee>0; Backup preauth inserted");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000), Ter(tecREQUIRES_FLAG));
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(firewall::setCreate(alice, alice, backup, 100000), Ter(temMALFORMED));
        env(firewall::setCreate(alice, cp, alice, 100000), Ter(temMALFORMED));
        env(firewall::setCreate(alice, cp, backup, 0), Ter(temMALFORMED));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000, std::nullopt, 10'000'000));
        env.close();
        auto const sle = env.le(fwKey(alice));
        BEAST_EXPECT(sle);
        BEAST_EXPECT(sle->getAccountID(sfCounterparty) == cp.id());
        BEAST_EXPECT(sle->isFieldPresent(sfMaxAmount));
        BEAST_EXPECT(!sle->isFieldPresent(sfBackup));
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), backup.id(), 0)));
        env(pay(alice, backup, XRP(1)));
        env.close();
    }

    void
    testDuplicateAndUnfunded()
    {
        testcase("second create tecDUPLICATE; unfunded CP/Backup tecNO_DST");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const ghost{"ghost"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000), Ter(tecDUPLICATE));
        Account const bob{"bob"};
        env.fund(XRP(10000), bob);
        env.close();
        env(fset(bob, asfWithdrawAuth));
        env.close();
        env(firewall::setCreate(bob, ghost, backup, 100000), Ter(tecNO_DST));
        env(firewall::setCreate(bob, cp, ghost, 100000), Ter(tecNO_DST));
        env.close();
    }

    void
    testUpdateNeedsCp()
    {
        testcase("update MaxFee/MaxAmount needs CounterpartySignature; Backup forbidden");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000, std::nullopt, 10'000'000));
        env.close();
        auto const id = fwKey(alice).key;
        env(firewall::setUpdateMaxFee(alice, id, 200000), Ter(tecREQUIRES_COUNTERPARTY));
        env(firewall::setUpdateMaxFee(alice, id, 200000), Sig(sfCounterpartySignature, cp));
        env.close();
        env(firewall::setUpdateMaxAmount(alice, id, 0), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.le(fwKey(alice))->isFieldPresent(sfMaxAmount));
        {
            json::Value jv = firewall::setUpdateMaxFee(alice, id, 100000);
            jv[sfBackup.jsonName] = backup.human();
            env(jv, Sig(sfCounterpartySignature, cp), Ter(temMALFORMED));
        }
        env.close();
    }

    void
    run() override
    {
        testDisabled();
        testCreateRequiresFlagAndFields();
        testDuplicateAndUnfunded();
        testUpdateNeedsCp();
    }
};

struct FirewallDelete_test : public beast::unit_test::Suite
{
    void
    testDisabledAndNoTarget()
    {
        testcase("temDISABLED; tecNO_TARGET without SLE / bad id");
        using namespace jtx;
        {
            Env env(*this, testableAmendments() - featureFirewall);
            Account const alice{"alice"};
            env.fund(XRP(10000), alice);
            env.close();
            env(firewall::del(alice, keylet::firewall(alice.id()).key), Ter(temDISABLED));
        }
        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        env.fund(XRP(10000), alice, cp);
        env.close();
        env(firewall::del(alice, keylet::firewall(alice.id()).key), Ter(tecNO_TARGET));
        env.close();
    }

    void
    testRequiresCpAndWipesOutbound()
    {
        testcase("CP required; lists kept unless tfClearWithdrawLists");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const bob{"bob"};
        env.fund(XRP(10000), alice, cp, backup, bob);
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000));
        env.close();
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        auto const id = keylet::firewall(alice.id()).key;
        env(firewall::del(alice, id), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(firewall::del(alice, id), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::firewall(alice.id())));
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), backup.id(), 0)));
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));

        env(firewall::setCreate(alice, cp, backup, 100000));
        env.close();
        auto const id2 = keylet::firewall(alice.id()).key;
        env(firewall::del(alice, id2, true), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::firewall(alice.id())));
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), backup.id(), 0)));
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
    }

    void
    run() override
    {
        testDisabledAndNoTarget();
        testRequiresCpAndWipesOutbound();
    }
};

struct DepositSetNoauth_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("DepositSetauth tfSetNoauthList only");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, bob, provider);
        env.close();
        env(fset(provider, asfDepositNoauth));
        env(depositnoauth::unauth(provider, bob));
        env.close();
        env(fset(alice, asfDepositNoauth));
        env.close();
        env(depositsetauth::setauth(alice, {provider}, true));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositSetNoauth(alice.id())));
        env(pay(bob, alice, XRP(1)), Ter(tecDEPOSIT_NOAUTH));
        env.close();
        env(depositsetauth::clear(alice, true));
        env.close();
        env(pay(bob, alice, XRP(1)));
        env.close();
    }
};

struct DepositSetPreauth_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("DepositSetauth tfSetPreauthList only");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, bob, provider);
        env.close();
        env(fset(provider, asfDepositAuth));
        env(deposit::auth(provider, bob));
        env.close();
        env(fset(alice, asfDepositAuth));
        env.close();
        env(pay(bob, alice, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
        env(depositsetauth::setauth(alice, {provider}, false));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositSetPreauth(alice.id())));
        env(pay(bob, alice, XRP(1)));
        env.close();
    }
};

struct WithdrawSetPreauth_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("WithdrawSetauth tfSetPreauthList only");
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
        env(withdrawauth::setauth(alice, {provider}, false));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawSetPreauth(alice.id())));
        env(pay(alice, bob, XRP(1)));
        env(pay(alice, carol, XRP(1)), Ter(tecNO_PERMISSION));
        env.close();
    }
};

struct WithdrawSetNoauth_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("WithdrawSetauth tfSetNoauthList only");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const provider{"provider"};
        env.fund(XRP(10000), alice, bob, provider);
        env.close();
        env(fset(provider, asfWithdrawNoauth));
        env(withdrawauth::noauth(provider, bob));
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env(fset(alice, asfWithdrawNoauth));
        env(withdrawauth::auth(alice, bob));
        env(withdrawauth::setauth(alice, {provider}, true));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawSetNoauth(alice.id())));
        env(pay(alice, bob, XRP(1)), Ter(tecWITHDRAW_NOAUTH));
        env.close();
    }
};

struct FirewallSetCreate_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("FirewallSet create only");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000), Ter(tecREQUIRES_FLAG));
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000));
        env.close();
        BEAST_EXPECT(env.closed()->exists(fwKey(alice)));
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), backup.id(), 0)));
        env(pay(alice, backup, XRP(1)));
        env(pay(alice, cp, XRP(1)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(firewall::setCreate(alice, cp, backup, 100000), Ter(tecDUPLICATE));
        env.close();
    }
};

struct FirewallSetUpdate_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("FirewallSet update: CP required, Backup forbidden, wrong id/CP");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        armFirewall(env, alice, cp, backup);
        auto const id = fwKey(alice).key;
        env(firewall::setUpdateMaxFee(alice, id, 200000), Ter(tecREQUIRES_COUNTERPARTY));
        env(firewall::setUpdateMaxFee(alice, uint256{}, 200000),
            Sig(sfCounterpartySignature, cp),
            Ter(tecNO_TARGET));
        env(firewall::setUpdateMaxFee(alice, id, 200000),
            Sig(sfCounterpartySignature, bob),
            Ter(tecREQUIRES_COUNTERPARTY));
        env(firewall::setUpdateMaxFee(alice, id, 200000), Sig(sfCounterpartySignature, cp));
        env.close();
        {
            json::Value jv = firewall::setUpdateMaxFee(alice, id, 100000);
            jv[sfBackup.jsonName] = backup.human();
            env(jv, Sig(sfCounterpartySignature, cp), Ter(temMALFORMED));
        }
        {
            json::Value jv;
            jv[jss::Account] = alice.human();
            jv[jss::TransactionType] = jss::FirewallSet;
            jv[sfFirewallID.jsonName] = to_string(id);
            jv[sfCounterparty.jsonName] = bob.human();
            env(jv, Sig(sfCounterpartySignature, cp));
        }
        env.close();
        BEAST_EXPECT(env.le(fwKey(alice))->getAccountID(sfCounterparty) == bob.id());
    }
};

struct FirewallSetMaxFee_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("MaxFee absolute tefFIREWALL_MAX_FEE; FirewallSet/Delete exempt");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        armFirewall(env, alice, cp, backup, /*maxFeeDrops=*/1000);
        auto const id = fwKey(alice).key;
        env(pay(alice, backup, XRP(1)), Fee(XRP(1)), Ter(tefFIREWALL_MAX_FEE));
        env(pay(alice, backup, XRP(1)),
            Fee(XRP(1)),
            Sig(sfCounterpartySignature, cp),
            Ter(tefFIREWALL_MAX_FEE));
        env.close();
        env(firewall::setUpdateMaxFee(alice, id, 2'000'000),
            Fee(XRP(1)),
            Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, backup, XRP(1)), Fee(XRP(1)));
        env.close();
        env(firewall::setUpdateMaxFee(alice, id, 1000),
            Fee(XRP(1)),
            Sig(sfCounterpartySignature, cp));
        env.close();
        env(firewall::del(alice, id), Fee(XRP(1)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(fwKey(alice)));
    }
};

struct FirewallSetMaxAmount_test : public beast::unit_test::Suite
{
    void
    run() override
    {
        testcase("MaxAmount 24h seed-alone cap; over cap needs CP; period reset");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        armFirewall(env, alice, cp, backup, 100000, /*maxAmountDrops=*/10'000'000);
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, bob, XRP(6)));
        env.close();
        BEAST_EXPECT(env.le(fwKey(alice))->at(sfMaxAmount) == XRP(10));
        BEAST_EXPECT(env.le(fwKey(alice))->at(sfTransferredAmount) == XRP(6));
        env(pay(alice, bob, XRP(5)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, bob, XRP(5)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.le(fwKey(alice))->at(sfTransferredAmount) == XRP(11));
        env.close(std::chrono::seconds(86400 + 10));
        env(pay(alice, bob, XRP(1)));
        env.close();
        BEAST_EXPECT(env.le(fwKey(alice))->at(sfTransferredAmount) == XRP(1));
        auto const id = fwKey(alice).key;
        env(firewall::setUpdateMaxAmount(alice, id, 0), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.le(fwKey(alice))->isFieldPresent(sfMaxAmount));
        env(pay(alice, bob, XRP(8)));
        env.close();
    }
};

BEAST_DEFINE_TESTSUITE(DepositNoauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(DepositSetauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(DepositSetNoauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(DepositSetPreauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(WithdrawPreauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(WithdrawNoauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(WithdrawSetauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(WithdrawSetPreauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(WithdrawSetNoauth, app, xrpl);
BEAST_DEFINE_TESTSUITE(FirewallSet, app, xrpl);
BEAST_DEFINE_TESTSUITE(FirewallSetCreate, app, xrpl);
BEAST_DEFINE_TESTSUITE(FirewallSetUpdate, app, xrpl);
BEAST_DEFINE_TESTSUITE(FirewallSetMaxFee, app, xrpl);
BEAST_DEFINE_TESTSUITE(FirewallSetMaxAmount, app, xrpl);
BEAST_DEFINE_TESTSUITE(FirewallDelete, app, xrpl);

}  // namespace xrpl::test
