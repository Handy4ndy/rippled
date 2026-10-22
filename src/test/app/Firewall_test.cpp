#include <test/jtx/AMM.h>
#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/TestHelpers.h>
#include <test/jtx/acctdelete.h>
#include <test/jtx/amount.h>
#include <test/jtx/batch.h>
#include <test/jtx/check.h>
#include <test/jtx/delegate.h>
#include <test/jtx/deposit.h>
#include <test/jtx/depositnoauth.h>
#include <test/jtx/escrow.h>
#include <test/jtx/fee.h>
#include <test/jtx/firewall.h>
#include <test/jtx/flags.h>
#include <test/jtx/mpt.h>
#include <test/jtx/multisign.h>
#include <test/jtx/offer.h>
#include <test/jtx/pay.h>
#include <test/jtx/paychan.h>
#include <test/jtx/regkey.h>
#include <test/jtx/require.h>
#include <test/jtx/rpc.h>
#include <test/jtx/sig.h>
#include <test/jtx/sponsor.h>
#include <test/jtx/ter.h>
#include <test/jtx/ticket.h>
#include <test/jtx/token.h>
#include <test/jtx/trust.h>
#include <test/jtx/txflags.h>
#include <test/jtx/withdrawauth.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/json/json_value.h>
#include <xrpl/ledger/helpers/PaymentPolicyHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/SeqProxy.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/jss.h>

#include <chrono>
#include <optional>

namespace xrpl::test {

struct Firewall_test : public beast::unit_test::Suite
{
    static Keylet
    fwKey(jtx::Account const& owner)
    {
        return keylet::firewall(owner.id());
    }

    void
    arm(jtx::Env& env,
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
        BEAST_EXPECT(env.closed()->exists(fwKey(owner)));
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(owner.id(), backup.id(), 0)));
    }

    void
    testDisabled()
    {
        testcase("FirewallSet/Delete temDISABLED without featureFirewall");
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
        env.close();
        env(firewall::del(alice, fwKey(alice).key), Ter(temDISABLED));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(fwKey(alice)));
    }

    void
    testCreateMalformed()
    {
        testcase("FirewallSet create malformed: missing fields, self CP/backup, zero caps");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        env(fset(alice, asfWithdrawAuth));
        env.close();

        {
            json::Value jv;
            jv[jss::Account] = alice.human();
            jv[jss::TransactionType] = jss::FirewallSet;
            env(jv, Ter(temMALFORMED));
        }
        env(firewall::setCreate(alice, alice, backup, 100000), Ter(temMALFORMED));
        env(firewall::setCreate(alice, cp, alice, 100000), Ter(temMALFORMED));
        env(firewall::setCreate(alice, cp, backup, 0), Ter(temMALFORMED));
        env(firewall::setCreate(alice, cp, backup, 100000, std::nullopt, 0), Ter(temMALFORMED));
        // Create forbids CounterpartySignatures the same as the single field.
        env(firewall::setCreate(alice, cp, backup, 100000),
            CpSigs({cp}),
            Fee(XRP(1)),
            Ter(temMALFORMED));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(fwKey(alice)));
    }

    void
    testCreateRequiresWithdrawAuth()
    {
        testcase("FirewallSet create requires asfWithdrawAuth");
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
        BEAST_EXPECT(env.le(fwKey(alice))->getAccountID(sfCounterparty) == cp.id());
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), backup.id(), 0)));
    }

    void
    testCreateDuplicateAndMissingDst()
    {
        testcase("FirewallSet create tecDUPLICATE; missing CP/backup account tecNO_DST");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const ghost{"ghost"};
        env.fund(XRP(10000), alice, cp, backup);
        env.close();
        arm(env, alice, cp, backup);

        env(firewall::setCreate(alice, cp, backup, 100000), Ter(tecDUPLICATE));
        env.close();

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
    testDestPolicyPreauthSeedVsCp()
    {
        testcase(
            "check-class: backup/preauth seed-only; unlisted needs CP; CP does not add preauth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const carol{"carol"};
        env.fund(XRP(10000), alice, bob, cp, backup, carol);
        env.close();
        arm(env, alice, cp, backup, 100000);

        env(pay(alice, carol, XRP(1)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, carol, XRP(1)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), carol.id(), 0)));

        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, bob, XRP(1)));
        env.close();
        env(pay(alice, backup, XRP(1)));
        env.close();

        env(withdrawauth::auth(alice, carol), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(withdrawauth::auth(alice, carol),
            Sig(sfCounterpartySignature, bob),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
    }

    void
    testDenyListAbsolute()
    {
        testcase("Firewall deny list is tecFIREWALL_BLOCK even with CP");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        env(fset(alice, asfWithdrawNoauth), Sig(sfCounterpartySignature, cp));
        env.close();
        env(withdrawauth::noauth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();

        env(pay(alice, bob, XRP(1)), Ter(tecFIREWALL_BLOCK));
        env.close();
        env(pay(alice, bob, XRP(1)), Sig(sfCounterpartySignature, cp), Ter(tecFIREWALL_BLOCK));
        env.close();

        // Pathing-class deny before CP.
        Account const gw{"gw"};
        auto const USD = gw["USD"];
        env.fund(XRP(10000), gw);
        env.close();
        env(trust(alice, USD(1000)));
        env(trust(bob, USD(1000)));
        env.close();
        env(pay(gw, alice, USD(100)));
        env.close();
        env(pay(alice, bob, USD(1)), Ter(tecFIREWALL_BLOCK));
        env.close();
        env(pay(alice, bob, USD(1)), Sig(sfCounterpartySignature, cp), Ter(tecFIREWALL_BLOCK));
        env.close();
    }

    void
    testMaxFeeAbsoluteAndExempt()
    {
        testcase("MaxFee is absolute tefFIREWALL_MAX_FEE; Set/Delete exempt only with CP");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup, /*maxFeeDrops=*/1000);
        auto const id = fwKey(alice).key;

        env(pay(alice, backup, XRP(1)), Fee(XRP(1)), Ter(tefFIREWALL_MAX_FEE));
        env.close();
        env(pay(alice, backup, XRP(1)),
            Fee(XRP(1)),
            Sig(sfCounterpartySignature, cp),
            Ter(tefFIREWALL_MAX_FEE));
        env.close();

        // Seed-only or wrong-CP over-MaxFee update/delete must stay tef (uncharged).
        env(firewall::setUpdateMaxFee(alice, id, 2'000'000), Fee(XRP(1)), Ter(tefFIREWALL_MAX_FEE));
        env.close();
        env(firewall::setUpdateMaxFee(alice, id, 2'000'000),
            Fee(XRP(1)),
            Sig(sfCounterpartySignature, bob),
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
        env(firewall::del(alice, id), Fee(XRP(1)), Ter(tefFIREWALL_MAX_FEE));
        env.close();
        env(firewall::del(alice, id), Fee(XRP(1)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(fwKey(alice)));
    }

    void
    testUpdateWrongIdAndWrongCp()
    {
        testcase("FirewallSet update tecNO_TARGET on bad id; wrong CP fails");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup);
        auto const id = fwKey(alice).key;

        env(firewall::setUpdateMaxFee(alice, uint256{}, 2000),
            Sig(sfCounterpartySignature, cp),
            Ter(tecNO_TARGET));
        env.close();
        env(firewall::setUpdateMaxFee(alice, id, 2000), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(firewall::setUpdateMaxFee(alice, id, 2000),
            Sig(sfCounterpartySignature, bob),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(firewall::del(alice, uint256{}), Sig(sfCounterpartySignature, cp), Ter(tecNO_TARGET));
        env.close();
    }

    void
    testKeySeal()
    {
        testcase("SetRegularKey, SignerListSet, DisableMaster, AccountDelete sealed");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup);

        env(regkey(alice, bob), Ter(tecFIREWALL_ACTIVE));
        env(regkey(alice, bob), Sig(sfCounterpartySignature, cp), Ter(tecFIREWALL_ACTIVE));
        env.close();
        BEAST_EXPECT(!env.le(alice)->isFieldPresent(sfRegularKey));

        env(signers(alice, 1, {{bob, 1}}), Ter(tecFIREWALL_ACTIVE));
        env(signers(alice, 1, {{bob, 1}}),
            Sig(sfCounterpartySignature, cp),
            Ter(tecFIREWALL_ACTIVE));
        env.close();
        BEAST_EXPECT(!env.le(keylet::signerList(alice.id())));

        env(fset(alice, asfDisableMaster), Sig(alice), Ter(tecFIREWALL_ACTIVE));
        env(fset(alice, asfDisableMaster),
            Sig(alice),
            Sig(sfCounterpartySignature, cp),
            Ter(tecFIREWALL_ACTIVE));
        env.close();
        env.require(Nflags(alice, asfDisableMaster));

        auto const acctDelFee = drops(env.current()->fees().increment);
        env(acctdelete(alice, bob), Fee(acctDelFee), Ter(tecFIREWALL_ACTIVE));
        env(acctdelete(alice, bob),
            Fee(acctDelFee),
            Sig(sfCounterpartySignature, cp),
            Ter(tecFIREWALL_ACTIVE));
        env.close();

        env(fclear(alice, asfWithdrawAuth),
            Sig(sfCounterpartySignature, cp),
            Ter(tecFIREWALL_ACTIVE));
        env.close();
        env.require(Flags(alice, asfWithdrawAuth));
    }

    void
    testManageClassNeedsCp()
    {
        testcase("manage-class AccountSet flags and deposit/withdraw lists need CP");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup);

        env(fset(alice, asfDepositAuth), Ter(tecREQUIRES_COUNTERPARTY));
        env(fset(alice, asfDepositNoauth), Ter(tecREQUIRES_COUNTERPARTY));
        env(fset(alice, asfWithdrawNoauth), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();

        env(fset(alice, asfDepositAuth), Sig(sfCounterpartySignature, cp));
        env.close();
        env.require(Flags(alice, asfDepositAuth));

        env(deposit::auth(alice, bob), Ter(tecREQUIRES_COUNTERPARTY));
        env(depositnoauth::unauth(alice, bob), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(deposit::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositPreauth(alice.id(), bob.id())));
        env(depositnoauth::unauth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::depositNoauth(alice.id(), bob.id())));

        env(withdrawauth::auth(alice, bob), Ter(tecREQUIRES_COUNTERPARTY));
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
    }

    void
    testAllowClass()
    {
        testcase("allow-class TicketCreate and TrustSet succeed without CP");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, cp, backup, gw);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        env(ticket::create(alice, 1));
        env.close();
        auto const USD = gw["USD"];
        env(trust(alice, USD(1000)));
        env.close();
        env(pay(gw, alice, USD(10)));
        env.close();
    }

    void
    testCheckClassCreatePaths()
    {
        testcase("check-class Escrow/Check/PayChan: backup seed, else CP");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const carol{"carol"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(100000), alice, carol, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        env(escrow::create(alice, carol, XRP(10)),
            escrow::kFinishTime(env.now() + 1s),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(escrow::create(alice, backup, XRP(10)), escrow::kFinishTime(env.now() + 1s));
        env.close();
        env(escrow::create(alice, carol, XRP(10)),
            escrow::kFinishTime(env.now() + 1s),
            Sig(sfCounterpartySignature, cp));
        env.close();

        env(check::create(alice, carol, XRP(5)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(check::create(alice, backup, XRP(5)));
        env.close();

        env(paychan::create(alice, carol, XRP(10), 3600s, alice.pk()),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(paychan::create(alice, backup, XRP(10), 3600s, alice.pk()));
        env.close();
    }

    void
    testBlockClass()
    {
        testcase("block-class OfferCreate needs CP; AMMCreate hits MaxFee first");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, bob, cp, backup, gw);
        env.close();

        auto const USD = gw["USD"];
        env(trust(alice, USD(1000)));
        env.close();
        env(pay(gw, alice, USD(100)));
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        env(offer(alice, XRP(10), USD(10)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(offer(alice, XRP(10), USD(10)), Sig(sfCounterpartySignature, cp));
        env.close();

        // AMMCreate's base fee is large; MaxFee is evaluated before block-class CP.
        AMM(env, alice, XRP(1000), USD(50), Ter(tefFIREWALL_MAX_FEE));
    }

    void
    testPathingClass()
    {
        testcase("pathing-class IOU/MPT Payment requires CP even to preauth dest");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const gw{"gw"};
        auto const USD = gw["USD"];
        env.fund(XRP(10000), alice, bob, cp, backup, gw);
        env.close();
        env(trust(alice, USD(1000)));
        env(trust(bob, USD(1000)));
        env.close();
        env(pay(gw, alice, USD(100)));
        env.close();

        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();
        arm(env, alice, cp, backup, 1'000'000);
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();

        env(pay(alice, bob, XRP(1)));
        env.close();
        env(pay(alice, bob, USD(1)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, bob, USD(1)), Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, bob, mptA(10)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, bob, mptA(10)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(mptA.getBalance(bob) == 1010);
    }

    void
    testMptOfferBlockClass()
    {
        testcase("block-class MPT OfferCreate requires CP");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, cp, backup, gw);
        env.close();
        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        env(offer(alice, mptA(10), XRP(10)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(offer(alice, mptA(10), XRP(10)), Sig(sfCounterpartySignature, cp));
        env.close();
    }

    void
    testMaxAmountDailyCap()
    {
        testcase(
            "MaxAmount: seed under cap, CP after cap, failed tx does not consume, period reset");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 100000, /*maxAmountDrops=*/10'000'000);
        auto const key = fwKey(alice);
        {
            auto const sle = env.le(key);
            BEAST_EXPECT(sle->at(sfMaxAmount) == XRP(10));
            BEAST_EXPECT(!sle->isFieldPresent(sfTransferredAmount));
        }
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();

        env(pay(alice, bob, XRP(6)));
        env.close();
        BEAST_EXPECT(env.le(key)->at(sfTransferredAmount) == XRP(6));

        env(pay(alice, bob, XRP(5)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        BEAST_EXPECT(env.le(key)->at(sfTransferredAmount) == XRP(6));

        env(pay(alice, bob, XRP(5)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(env.le(key)->at(sfTransferredAmount) == XRP(11));

        env.close(std::chrono::seconds(86400 + 10));
        env(pay(alice, bob, XRP(1)));
        env.close();
        BEAST_EXPECT(env.le(key)->at(sfTransferredAmount) == XRP(1));
    }

    void
    testMaxAmountDoesNotRewriteDestOrMaxFee()
    {
        testcase("MaxAmount does not rewrite dest policy, MaxFee, or count MPT");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const carol{"carol"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, cp, backup, carol, gw);
        env.close();
        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();
        arm(env, alice, cp, backup, 100000, 100'000'000);
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();

        env(pay(alice, carol, XRP(1)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, carol, XRP(1)), Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, bob, XRP(1)), Fee(XRP(1)), Ter(tefFIREWALL_MAX_FEE));
        env.close();
        env(pay(alice, bob, XRP(1)));
        env.close();
        env(pay(alice, bob, mptA(10)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, bob, mptA(10)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(mptA.getBalance(bob) == 1010);
        BEAST_EXPECT(env.le(fwKey(alice))->at(sfTransferredAmount) == XRP(2));
    }

    void
    testMaxAmountUpdateAndClear()
    {
        testcase("MaxAmount update/clear requires CP; 0 wipes accumulator");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 100000, 5'000'000);
        auto const id = fwKey(alice).key;
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();

        env(pay(alice, bob, XRP(5)));
        env.close();
        env(pay(alice, bob, XRP(1)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();

        env(firewall::setUpdateMaxAmount(alice, id, 20'000'000), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(firewall::setUpdateMaxAmount(alice, id, 20'000'000), Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, bob, XRP(1)));
        env.close();
        BEAST_EXPECT(env.le(fwKey(alice))->at(sfTransferredAmount) == XRP(6));

        env(firewall::setUpdateMaxAmount(alice, id, 0), Sig(sfCounterpartySignature, cp));
        env.close();
        {
            auto const sle = env.le(fwKey(alice));
            BEAST_EXPECT(!sle->isFieldPresent(sfMaxAmount));
            BEAST_EXPECT(!sle->isFieldPresent(sfTransferredAmount));
            BEAST_EXPECT(!sle->isFieldPresent(sfPeriodStart));
        }
        env(pay(alice, bob, XRP(50)));
        env.close();
    }

    void
    testDeleteWipesOutbound()
    {
        testcase("FirewallDelete keeps outbound lists unless tfClearWithdrawLists");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup);
        auto const key = fwKey(alice);
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();

        env(firewall::del(alice, key.key), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        // Default delete: Firewall SLE only; user and backup preauths remain.
        env(firewall::del(alice, key.key), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(key));
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), backup.id(), 0)));
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));

        env(pay(alice, bob, XRP(1)));
        env.close();

        // Re-arm (reuses leftover backup preauth). Bob's preauth from the soft
        // delete is still present, so wipe-delete can clear both without re-auth.
        arm(env, alice, cp, backup);
        auto const key2 = fwKey(alice);
        BEAST_EXPECT(env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
        env(firewall::del(alice, key2.key, true), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(!env.closed()->exists(key2));
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), backup.id(), 0)));
        BEAST_EXPECT(!env.closed()->exists(keylet::withdrawPreauth(alice.id(), bob.id(), 0)));
    }

    void
    testActionClassifiesAllTxTypes()
    {
        testcase("firewallActionFor classifies every known TxType (fail-closed default)");
        using namespace jtx;

        for (auto const& format : TxFormats::getInstance())
        {
            auto const tt = format.getType();
            auto const action = firewallActionFor(tt);
            // default must not be allow for anything the matrix forgot; allow
            // is only for the explicit allow list plus system/manage/check/block.
            if (action == FirewallAction::allow)
            {
                BEAST_EXPECT(
                    tt == ttTICKET_CREATE || tt == ttTRUST_SET || tt == ttDELEGATE_SET ||
                    tt == ttDID_SET || tt == ttDID_DELETE || tt == ttORACLE_SET ||
                    tt == ttORACLE_DELETE || tt == ttNFTOKEN_CANCEL_OFFER ||
                    tt == ttNFTOKEN_MODIFY || tt == ttOFFER_CANCEL || tt == ttCHECK_CANCEL ||
                    tt == ttESCROW_CANCEL || tt == ttCLAWBACK || tt == ttAMM_CLAWBACK ||
                    tt == ttAMM_VOTE || tt == ttAMM_DELETE || tt == ttVAULT_CREATE ||
                    tt == ttVAULT_SET || tt == ttVAULT_DELETE || tt == ttVAULT_CLAWBACK ||
                    tt == ttLOAN_BROKER_SET || tt == ttLOAN_BROKER_DELETE ||
                    tt == ttLOAN_BROKER_COVER_CLAWBACK || tt == ttLOAN_SET || tt == ttLOAN_DELETE ||
                    tt == ttLOAN_MANAGE || tt == ttCREDENTIAL_CREATE || tt == ttCREDENTIAL_ACCEPT ||
                    tt == ttCREDENTIAL_DELETE || tt == ttMPTOKEN_ISSUANCE_CREATE ||
                    tt == ttMPTOKEN_ISSUANCE_DESTROY || tt == ttMPTOKEN_ISSUANCE_SET ||
                    tt == ttMPTOKEN_AUTHORIZE || tt == ttPERMISSIONED_DOMAIN_SET ||
                    tt == ttPERMISSIONED_DOMAIN_DELETE || tt == ttCONFIDENTIAL_MPT_CLAWBACK ||
                    tt == ttCONFIDENTIAL_MPT_MIRROR_UPDATE ||
                    tt == ttCONFIDENTIAL_MPT_HOLDER_KEY_UPDATE ||
                    tt == ttTRANSACTION_PROPOSAL_CREATE || tt == ttTRANSACTION_PROPOSAL_CANCEL ||
                    tt == ttLEDGER_STATE_FIX || tt == ttBATCH);
            }
            else
            {
                BEAST_EXPECT(
                    action == FirewallAction::check || action == FirewallAction::block ||
                    action == FirewallAction::manage || action == FirewallAction::system);
            }
        }
    }

    void
    testSoftPolicyUnchangedWithoutFirewall()
    {
        testcase("Without Firewall SLE, Payment Policy TECs are unchanged");
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
        env(pay(alice, bob, XRP(1)));
        env.close();
    }

    void
    testRestingOfferDroppedWhenFirewalled()
    {
        testcase("Resting offers of a firewalled owner are not crossed");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, cp, backup, gw);
        env.close();
        MPTTester mptA({.env = env, .issuer = gw, .holders = {alice, bob}, .pay = 1000});
        env.close();

        env(offer(alice, XRP(50), mptA(50)));
        env.close();
        BEAST_EXPECT(mptA.getBalance(alice) == 1000);

        arm(env, alice, cp, backup, 1'000'000);
        env(offer(bob, mptA(50), XRP(50)));
        env.close();
        BEAST_EXPECT(mptA.getBalance(alice) == 1000);
        BEAST_EXPECT(mptA.getBalance(bob) == 1000);
    }

    void
    testBatchCannotBypass()
    {
        testcase("Batch inner txs still hit Firewall dest policy and MaxFee");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const carol{"carol"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, carol, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        auto const batchFee = batch::calcBatchFee(env, 0, 2);

        {
            auto const preCarol = env.balance(carol);
            auto const seq = env.seq(alice);
            env(batch::outer(alice, seq, batchFee, tfAllOrNothing),
                batch::Inner(pay(alice, carol, XRP(10)), seq + 1),
                batch::Inner(pay(alice, carol, XRP(1)), seq + 2));
            env.close();
            BEAST_EXPECT(env.balance(carol) == preCarol);
        }

        {
            auto const preBackup = env.balance(backup);
            auto const preCarol = env.balance(carol);
            auto const seq = env.seq(alice);
            env(batch::outer(alice, seq, batchFee, tfIndependent),
                batch::Inner(pay(alice, backup, XRP(2)), seq + 1),
                batch::Inner(pay(alice, carol, XRP(2)), seq + 2));
            env.close();
            BEAST_EXPECT(env.balance(backup) == preBackup + XRP(2));
            BEAST_EXPECT(env.balance(carol) == preCarol);
        }

        {
            auto const fwId = fwKey(alice).key;
            env(firewall::setUpdateMaxFee(alice, fwId, 1000), Sig(sfCounterpartySignature, cp));
            env.close();
            auto const seq = env.seq(alice);
            env(batch::outer(alice, seq, XRP(1), tfAllOrNothing),
                batch::Inner(pay(alice, backup, XRP(1)), seq + 1),
                batch::Inner(pay(alice, backup, XRP(1)), seq + 2),
                Ter(tefFIREWALL_MAX_FEE));
            env.close();
        }

        // Block-class inner cannot carry CP; AllOrNothing leaves no offer.
        // Outer Batch doApply is always tesSUCCESS; assert side effects.
        {
            Account const gw{"gw"};
            env.fund(XRP(10000), gw);
            env.close();
            auto const USD = gw["USD"];
            env(trust(alice, USD(1000)));
            env.close();
            env(pay(gw, alice, USD(100)));
            env.close();
            // Restore a usable MaxFee after the prior over-fee Batch case.
            env(firewall::setUpdateMaxFee(alice, fwKey(alice).key, 1'000'000),
                Sig(sfCounterpartySignature, cp));
            env.close();
            auto const preBackup = env.balance(backup);
            auto const preUsd = env.balance(alice, USD);
            auto const seq = env.seq(alice);
            auto const fee = batch::calcBatchFee(env, 0, 2);
            env(batch::outer(alice, seq, fee, tfAllOrNothing),
                batch::Inner(pay(alice, backup, XRP(1)), seq + 1),
                batch::Inner(offer(alice, XRP(10), USD(10)), seq + 2));
            env.close();
            BEAST_EXPECT(env.balance(backup) == preBackup);
            BEAST_EXPECT(env.balance(alice, USD) == preUsd);
            BEAST_EXPECT(
                env.le(keylet::offer(alice.id(), SeqProxy::rawSequence(seq + 2))) == nullptr);
        }
    }

    void
    testNftBuyAcceptNeedsCp()
    {
        testcase("NFTokenAcceptOffer buy: firewalled seller needs CP unless buyer preauth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();

        // Mint before Firewall so check-class NFTokenMint is not under test here.
        auto const nftId = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        auto const nftId2 = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        auto const nftId3 = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();

        auto const buyOffer = keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
        env(token::createOffer(bob, nftId, drops(1)), token::Owner(alice));
        env.close();
        auto const buyOffer2 =
            keylet::nftokenOffer(backup, SeqProxy::rawSequence(env.seq(backup))).key;
        env(token::createOffer(backup, nftId2, drops(1)), token::Owner(alice));
        env.close();

        arm(env, alice, cp, backup, 1'000'000);
        env(token::acceptBuyOffer(alice, buyOffer), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(token::acceptBuyOffer(alice, buyOffer), Sig(sfCounterpartySignature, cp));
        env.close();

        // Backup is Withdraw-preauth'd by FirewallSet create.
        env(token::acceptBuyOffer(alice, buyOffer2));
        env.close();

        env(token::burn(alice, nftId3), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(token::burn(alice, nftId3), Sig(sfCounterpartySignature, cp));
        env.close();

        // Brokered: subject is sell-offer owner (alice), not the broker.
        auto const nftId4 = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable), Sig(sfCounterpartySignature, cp));
        env.close();
        auto const sellOffer =
            keylet::nftokenOffer(alice, SeqProxy::rawSequence(env.seq(alice))).key;
        env(token::createOffer(alice, nftId4, drops(1)),
            Txflags(tfSellNFToken),
            Sig(sfCounterpartySignature, cp));
        env.close();
        auto const buyOffer3 = keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
        env(token::createOffer(bob, nftId4, drops(1)), token::Owner(alice));
        env.close();
        Account const broker{"broker"};
        env.fund(XRP(10000), broker);
        env.close();
        env(token::brokerOffers(broker, buyOffer3, sellOffer), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(token::brokerOffers(broker, buyOffer3, sellOffer), Sig(sfCounterpartySignature, cp));
        env.close();
    }

    void
    testNftBuyAcceptFirewalledBuyer()
    {
        testcase("NFTokenAcceptOffer buy: firewalled buyer needs seller preauth or CP");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, carol, cp, backup);
        env.close();

        // Bob (buyer) is firewalled; alice (seller) is not. Buy accept must seal bob.
        auto const nftId = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        auto const nftId2 = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();

        arm(env, bob, cp, backup, 1'000'000);

        auto const buyOffer = keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
        env(token::createOffer(bob, nftId, drops(1)),
            token::Owner(alice),
            Sig(sfCounterpartySignature, cp));
        env.close();
        env(token::acceptBuyOffer(alice, buyOffer), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(token::acceptBuyOffer(alice, buyOffer), Sig(sfCounterpartySignature, cp));
        env.close();

        env(withdrawauth::auth(bob, carol), Sig(sfCounterpartySignature, cp));
        env.close();
        auto const buyOffer2 = keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
        env(token::createOffer(bob, nftId2, drops(1)),
            token::Owner(alice),
            Sig(sfCounterpartySignature, cp));
        env.close();
        // Preauth carol does not authorize payment to alice.
        env(token::acceptBuyOffer(alice, buyOffer2), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(withdrawauth::auth(bob, alice), Sig(sfCounterpartySignature, cp));
        env.close();
        env(token::acceptBuyOffer(alice, buyOffer2));
        env.close();
    }

    void
    testNftBrokeredBuyerBrokerCut()
    {
        testcase(
            "NFTokenAcceptOffer brokered: firewalled buyer needs broker+seller "
            "preauth or CP when BrokerFee set");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const broker{"broker"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, broker, cp, backup);
        env.close();

        auto const nftId = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        auto const nftId2 = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();

        arm(env, bob, cp, backup, 1'000'000);

        // Seller-only preauth is enough when there is no broker cut.
        env(withdrawauth::auth(bob, alice), Sig(sfCounterpartySignature, cp));
        env.close();
        {
            auto const sellOffer =
                keylet::nftokenOffer(alice, SeqProxy::rawSequence(env.seq(alice))).key;
            env(token::createOffer(alice, nftId, drops(10)), Txflags(tfSellNFToken));
            env.close();
            auto const buyOffer =
                keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
            env(token::createOffer(bob, nftId, drops(100)),
                token::Owner(alice),
                Sig(sfCounterpartySignature, cp));
            env.close();
            env(token::brokerOffers(broker, buyOffer, sellOffer));
            env.close();
        }

        // BrokerFee with seller-only preauth still needs CP (broker unlisted).
        {
            auto const sellOffer =
                keylet::nftokenOffer(alice, SeqProxy::rawSequence(env.seq(alice))).key;
            env(token::createOffer(alice, nftId2, drops(10)), Txflags(tfSellNFToken));
            env.close();
            auto const buyOffer =
                keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
            env(token::createOffer(bob, nftId2, drops(100)),
                token::Owner(alice),
                Sig(sfCounterpartySignature, cp));
            env.close();
            env(token::brokerOffers(broker, buyOffer, sellOffer),
                token::BrokerFee(drops(1)),
                Ter(tecREQUIRES_COUNTERPARTY));
            env.close();
            env(token::brokerOffers(broker, buyOffer, sellOffer),
                token::BrokerFee(drops(1)),
                Sig(sfCounterpartySignature, cp));
            env.close();
        }

        // Preauth broker + seller: seed brokered accept with BrokerFee, no CP.
        auto const nftId3 = token::getNextID(env, alice, 0, tfTransferable);
        env(token::mint(alice, 0), Txflags(tfTransferable));
        env.close();
        env(withdrawauth::auth(bob, broker), Sig(sfCounterpartySignature, cp));
        env.close();
        {
            auto const sellOffer =
                keylet::nftokenOffer(alice, SeqProxy::rawSequence(env.seq(alice))).key;
            env(token::createOffer(alice, nftId3, drops(10)), Txflags(tfSellNFToken));
            env.close();
            auto const buyOffer =
                keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
            env(token::createOffer(bob, nftId3, drops(100)),
                token::Owner(alice),
                Sig(sfCounterpartySignature, cp));
            env.close();
            env(token::brokerOffers(broker, buyOffer, sellOffer), token::BrokerFee(drops(1)));
            env.close();
        }
    }

    void
    testDualFirewallSameCounterparty()
    {
        testcase("Dual firewalled subjects: same CP single sig; different CPs via array");
        using namespace jtx;

        // NFT buy-accept: firewalled seller (primary) + firewalled buyer (additional).
        {
            Env env(*this);
            Account const alice{"alice"};
            Account const bob{"bob"};
            Account const cp{"cp"};
            Account const backup{"backup"};
            env.fund(XRP(10000), alice, bob, cp, backup);
            env.close();

            auto const nftId = token::getNextID(env, alice, 0, tfTransferable);
            env(token::mint(alice, 0), Txflags(tfTransferable));
            env.close();

            arm(env, alice, cp, backup, 1'000'000);
            arm(env, bob, cp, backup, 1'000'000);

            auto const buyOffer =
                keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
            env(token::createOffer(bob, nftId, drops(1)),
                token::Owner(alice),
                Sig(sfCounterpartySignature, cp));
            env.close();
            // Neither side preauth'd the other: both need cosign; shared CP works.
            env(token::acceptBuyOffer(alice, buyOffer), Ter(tecREQUIRES_COUNTERPARTY));
            env.close();
            env(token::acceptBuyOffer(alice, buyOffer), Sig(sfCounterpartySignature, cp));
            env.close();
        }

        // Different Counterparties: CounterpartySignatures seals both.
        {
            Env envDiff(*this);
            Account const seller{"seller"};
            Account const buyer{"buyer"};
            Account const cpA{"cpA"};
            Account const cpB{"cpB"};
            Account const bakA{"bakA"};
            Account const bakB{"bakB"};
            envDiff.fund(XRP(10000), seller, buyer, cpA, cpB, bakA, bakB);
            envDiff.close();
            auto const nftDiff = token::getNextID(envDiff, seller, 0, tfTransferable);
            envDiff(token::mint(seller, 0), Txflags(tfTransferable));
            envDiff.close();
            arm(envDiff, seller, cpA, bakA, 1'000'000);
            arm(envDiff, buyer, cpB, bakB, 1'000'000);
            auto const buyDiff =
                keylet::nftokenOffer(buyer, SeqProxy::rawSequence(envDiff.seq(buyer))).key;
            envDiff(
                token::createOffer(buyer, nftDiff, drops(1)),
                token::Owner(seller),
                Sig(sfCounterpartySignature, cpB));
            envDiff.close();
            // One single-field CP cannot satisfy both Firewalls.
            envDiff(
                token::acceptBuyOffer(seller, buyDiff),
                Sig(sfCounterpartySignature, cpA),
                Ter(tecREQUIRES_COUNTERPARTY));
            envDiff.close();
            envDiff(token::acceptBuyOffer(seller, buyDiff), CpSigs({cpA, cpB}), Fee(XRP(1)));
            envDiff.close();
        }

        // Payment + firewalled reserve sponsor: same CP seals both; array for different CPs.
        {
            Env env(*this);
            Account const alice{"alice"};
            Account const sponsor{"sponsor"};
            Account const carol{"carol"};
            Account const cp{"cp"};
            Account const backup{"backup"};
            env.fund(XRP(100000), alice, sponsor, carol, cp, backup);
            env.close();
            arm(env, alice, cp, backup, 1'000'000);
            arm(env, sponsor, cp, backup, 1'000'000);

            env(pay(alice, carol, XRP(1)),
                Fee(XRP(1)),
                sponsor::As(sponsor, spfSponsorReserve),
                Sig(sfSponsorSignature, sponsor),
                Ter(tecREQUIRES_COUNTERPARTY));
            env.close();
            env(pay(alice, carol, XRP(1)),
                Fee(XRP(1)),
                sponsor::As(sponsor, spfSponsorReserve),
                Sig(sfSponsorSignature, sponsor),
                Sig(sfCounterpartySignature, cp));
            env.close();

            Env envDiff(*this);
            Account const alice2{"alice2"};
            Account const sponsor2{"sponsor2"};
            Account const carol2{"carol2"};
            Account const cpA{"cpA"};
            Account const cpB{"cpB"};
            Account const bakA{"bakA"};
            Account const bakB{"bakB"};
            envDiff.fund(XRP(100000), alice2, sponsor2, carol2, cpA, cpB, bakA, bakB);
            envDiff.close();
            arm(envDiff, alice2, cpA, bakA, 1'000'000);
            arm(envDiff, sponsor2, cpB, bakB, 1'000'000);
            envDiff(
                pay(alice2, carol2, XRP(1)),
                Fee(XRP(1)),
                sponsor::As(sponsor2, spfSponsorReserve),
                Sig(sfSponsorSignature, sponsor2),
                Sig(sfCounterpartySignature, cpA),
                Ter(tecREQUIRES_COUNTERPARTY));
            envDiff.close();
            envDiff(
                pay(alice2, carol2, XRP(1)),
                Fee(XRP(1)),
                sponsor::As(sponsor2, spfSponsorReserve),
                Sig(sfSponsorSignature, sponsor2),
                CpSigs({cpA, cpB}));
            envDiff.close();
        }

        // Allow-class TrustSet: only the firewalled sponsor needs CP, so a
        // different Counterparty on an unarmed submitter is irrelevant.
        {
            Env env(*this);
            Account const alice{"alice"};
            Account const sponsor{"sponsor"};
            Account const cp{"cp"};
            Account const backup{"backup"};
            Account const gw{"gw"};
            env.fund(XRP(100000), alice, sponsor, cp, backup, gw);
            env.close();
            arm(env, sponsor, cp, backup, 1'000'000);
            auto const USD = gw["USD"];
            env(trust(alice, USD(1000)),
                Fee(XRP(1)),
                sponsor::As(sponsor, spfSponsorReserve),
                Sig(sfSponsorSignature, sponsor),
                Sig(sfCounterpartySignature, cp));
            env.close();
        }
    }

    void
    testCounterpartySignaturesMalformed()
    {
        testcase("CounterpartySignature and CounterpartySignatures are mutually exclusive");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        // Both single and array on one Payment.
        env(pay(alice, bob, XRP(1)),
            Sig(sfCounterpartySignature, cp),
            CpSigs({cp}),
            Fee(XRP(1)),
            Ter(temMALFORMED));
        env.close();

        // Oversized array (max 3): rejected in checkSign before preflight.
        Account const cp2{"cp2"};
        Account const cp3{"cp3"};
        Account const cp4{"cp4"};
        env.fund(XRP(10000), cp2, cp3, cp4);
        env.close();
        env(pay(alice, bob, XRP(1)),
            CpSigs({cp, cp2, cp3, cp4}),
            Fee(XRP(1)),
            Rpc("invalidTransaction",
                "fails local checks: CounterpartySignatures array size "
                "invalid."));
        env.close();

        // Empty array: rejected in checkSign before preflight.
        {
            json::Value jv;
            jv[jss::Account] = alice.human();
            jv[jss::TransactionType] = jss::Payment;
            jv[jss::Destination] = bob.human();
            jv[jss::Amount] = "1000000";
            jv[sfCounterpartySignatures.getJsonName()] = json::Value{json::ValueType::Array};
            env(jv,
                Rpc("invalidTransaction",
                    "fails local checks: CounterpartySignatures array size "
                    "invalid."));
            env.close();
        }
    }

    void
    testCheckCashTaggedPreauth()
    {
        testcase("CheckCash uses check DestinationTag for Firewall preauth");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        std::uint32_t const tag = 42;
        env(withdrawauth::auth(alice, bob, tag), Sig(sfCounterpartySignature, cp));
        env.close();
        auto const checkBad = keylet::check(alice.id(), SeqProxy::rawSequence(env.seq(alice))).key;
        // Create under CP: bob@99 is not preauth (only bob@42 is).
        env(check::create(alice, bob, XRP(5)), DestTag(99), Sig(sfCounterpartySignature, cp));
        env.close();
        env(check::cash(bob, checkBad, XRP(5)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(check::cash(bob, checkBad, XRP(5)), Sig(sfCounterpartySignature, cp));
        env.close();

        auto const checkId = keylet::check(alice.id(), SeqProxy::rawSequence(env.seq(alice))).key;
        env(check::create(alice, bob, XRP(5)), DestTag(tag));
        env.close();
        // Casher is bob; Firewall subject is alice (creator). Tag must match.
        env(check::cash(bob, checkId, XRP(5)));
        env.close();
    }

    void
    testPayChanOwnerCloseWithoutDestPreauth()
    {
        testcase("PayChanClaim owner close/renew without Balance skips dest preauth");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const carol{"carol"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, carol, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        // Channel to carol (not preauth). Owner close without claim must work
        // seed-alone: funds refund to the owner after settleDelay.
        auto const chan = paychan::channel(alice, carol, env.seq(alice));
        env(paychan::create(alice, carol, XRP(10), 3600s, alice.pk()),
            Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(paychan::channelExists(*env.closed(), chan));
        env(paychan::claim(alice, chan), Txflags(tfRenew));
        env.close();
        env(paychan::claim(alice, chan), Txflags(tfClose));
        env.close();
        auto const sleChan = env.closed()->read(Keylet{ltPAYCHAN, chan});
        BEAST_EXPECT(sleChan);
        BEAST_EXPECT(sleChan->isFieldPresent(sfExpiration));

        // Claim with Balance still requires dest preauth or CP.
        auto const chan2 = paychan::channel(alice, carol, env.seq(alice));
        env(paychan::create(alice, carol, XRP(10), 3600s, alice.pk()),
            Sig(sfCounterpartySignature, cp));
        env.close();
        env(paychan::claim(alice.id(), chan2, XRP(1), XRP(1)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(paychan::claim(alice.id(), chan2, XRP(1), XRP(1)), Sig(sfCounterpartySignature, cp));
        env.close();
        BEAST_EXPECT(paychan::channelBalance(*env.closed(), chan2) == XRP(1));
    }

    void
    testNftSellOnlyBuyerFirewall()
    {
        testcase("NFTokenAcceptOffer sell-only: firewalled buyer needs seller preauth or CP");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();

        auto const nftId = token::getNextID(env, bob, 0, tfTransferable);
        env(token::mint(bob, 0), Txflags(tfTransferable));
        env.close();
        auto const sellOffer = keylet::nftokenOffer(bob, SeqProxy::rawSequence(env.seq(bob))).key;
        env(token::createOffer(bob, nftId, drops(1)), Txflags(tfSellNFToken));
        env.close();

        arm(env, alice, cp, backup, 1'000'000);
        env(token::acceptSellOffer(alice, sellOffer), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(token::acceptSellOffer(alice, sellOffer), Sig(sfCounterpartySignature, cp));
        env.close();
    }

    void
    testExpiredWithdrawNoauthUnderFirewall()
    {
        testcase("Expired WithdrawNoauth is not live under Firewall deny");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        env(fset(alice, asfWithdrawNoauth), Sig(sfCounterpartySignature, cp));
        env.close();
        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        auto const now = env.now().time_since_epoch().count();
        std::uint32_t const exp = static_cast<std::uint32_t>(now + 3600);
        env(withdrawauth::noauth(alice, bob, exp), Sig(sfCounterpartySignature, cp));
        env.close();

        env(pay(alice, bob, XRP(1)), Ter(tecFIREWALL_BLOCK));
        env.close();
        env.close(std::chrono::seconds(4000));
        // Expired deny is not live; bob remains Withdraw-preauth'd.
        env(pay(alice, bob, XRP(1)));
        env.close();
    }

    void
    testEscrowFinishAroundFirewall()
    {
        testcase("Escrow finish: pre-firewall object and firewalled destination");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(10000), alice, bob, carol, cp, backup);
        env.close();

        // Create escrow before Firewall; finish after arm still seals alice.
        auto const seqPre = env.seq(alice);
        env(escrow::create(alice, bob, XRP(5)), escrow::kFinishTime(env.now() + 1s));
        env.close();
        arm(env, alice, cp, backup, 1'000'000);
        env.close(std::chrono::seconds(2));
        // bob not preauth → finish needs alice CP (subject = escrow owner).
        env(escrow::finish(bob, alice, seqPre), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(escrow::finish(bob, alice, seqPre), Sig(sfCounterpartySignature, cp));
        env.close();

        // Firewalled destination finishing inbound escrow (carol firewalled).
        Account const cpC{"cpC"};
        Account const backupC{"backupC"};
        env.fund(XRP(10000), cpC, backupC);
        env.close();
        arm(env, carol, cpC, backupC, 1'000'000);
        auto const seqBob = env.seq(bob);
        env(escrow::create(bob, carol, XRP(5)), escrow::kFinishTime(env.now() + 1s));
        env.close();
        env.close(std::chrono::seconds(2));
        // Funds leave bob (no Firewall) to carol; carol's Firewall is inbound-only
        // via Payment Policy. Finish succeeds without carol CP.
        env(escrow::finish(carol, bob, seqBob));
        env.close();
    }

    void
    testSoftBurnNeedsWithdrawAuth()
    {
        testcase("Soft PP: self-burn blocked by WithdrawAuth without Firewall");
        using namespace jtx;

        Env env(*this, testableAmendments() - featureFirewall);
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
    testReserveSponsorNeedsCp()
    {
        testcase(
            "Firewalled reserve sponsor needs CP on SponsorshipTransfer, TrustSet, DelegateSet");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const sponsor{"sponsor"};
        Account const bob{"bob"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const gw{"gw"};
        env.fund(XRP(100000), alice, sponsor, bob, cp, backup, gw);
        env.close();
        arm(env, sponsor, cp, backup, 1'000'000);

        env(sponsor::transfer(alice, tfSponsorshipCreate),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(sponsor::transfer(alice, tfSponsorshipCreate),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Sig(sfCounterpartySignature, cp));
        env.close();

        // TrustSet is on the v1 reserve-sponsor allow-list.
        auto const USD = gw["USD"];
        env(trust(alice, USD(1000)),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(trust(alice, USD(1000)),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Sig(sfCounterpartySignature, cp));
        env.close();

        // DelegateSet is also reserve-sponsor-allowed and must carry CP fields.
        env(delegate::set(alice, bob, {"Payment"}),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(delegate::set(alice, bob, {"Payment"}),
            Fee(XRP(1)),
            sponsor::As(sponsor, spfSponsorReserve),
            Sig(sfSponsorSignature, sponsor),
            Sig(sfCounterpartySignature, cp));
        env.close();
    }

    void
    testSponsorshipSetCounterpartySponsorNeedsCp()
    {
        testcase("SponsorshipSet: firewalled CounterpartySponsor needs CP on delete");
        using namespace jtx;

        // Account is the sponsee; CounterpartySponsor is the firewalled sponsor.
        Env env(*this);
        Account const alice{"alice"};
        Account const sponsor{"sponsor"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(100000), alice, sponsor, cp, backup);
        env.close();

        env(sponsor::set(sponsor, 0, 100, XRP(1000)), sponsor::SponseeAcc(alice));
        env.close();

        arm(env, sponsor, cp, backup, 1'000'000);

        env(sponsor::set(alice, tfDeleteObject),
            sponsor::CounterpartySponsor(sponsor),
            Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(sponsor::set(alice, tfDeleteObject),
            sponsor::CounterpartySponsor(sponsor),
            Sig(sfCounterpartySignature, cp));
        env.close();
    }

    void
    testPayChanFundPreauthWithoutCp()
    {
        testcase("PayChanFund: preauth channel dest allows seed fund; else CP");
        using namespace jtx;
        using namespace std::chrono_literals;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        env.fund(XRP(100000), alice, bob, carol, cp, backup);
        env.close();
        arm(env, alice, cp, backup, 1'000'000);

        env(withdrawauth::auth(alice, bob), Sig(sfCounterpartySignature, cp));
        env.close();
        auto const seqBob = env.seq(alice);
        env(paychan::create(alice, bob, XRP(10), 3600s, alice.pk()));
        env.close();
        auto const chanBob = paychan::channel(alice, bob, seqBob);
        env(paychan::fund(alice.id(), chanBob, XRP(5)));
        env.close();

        auto const seqCarol = env.seq(alice);
        env(paychan::create(alice, carol, XRP(10), 3600s, alice.pk()),
            Sig(sfCounterpartySignature, cp));
        env.close();
        auto const chanCarol = paychan::channel(alice, carol, seqCarol);
        env(paychan::fund(alice.id(), chanCarol, XRP(5)), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(paychan::fund(alice.id(), chanCarol, XRP(5)), Sig(sfCounterpartySignature, cp));
        env.close();
    }

    void
    run() override
    {
        testDisabled();
        testCreateMalformed();
        testCreateRequiresWithdrawAuth();
        testCreateDuplicateAndMissingDst();
        testDestPolicyPreauthSeedVsCp();
        testDenyListAbsolute();
        testMaxFeeAbsoluteAndExempt();
        testUpdateWrongIdAndWrongCp();
        testKeySeal();
        testManageClassNeedsCp();
        testAllowClass();
        testCheckClassCreatePaths();
        testBlockClass();
        testPathingClass();
        testMptOfferBlockClass();
        testMaxAmountDailyCap();
        testMaxAmountDoesNotRewriteDestOrMaxFee();
        testMaxAmountUpdateAndClear();
        testDeleteWipesOutbound();
        testActionClassifiesAllTxTypes();
        testSoftPolicyUnchangedWithoutFirewall();
        testRestingOfferDroppedWhenFirewalled();
        testBatchCannotBypass();
        testDelegateCannotBypass();
        testNftBuyAcceptNeedsCp();
        testNftBuyAcceptFirewalledBuyer();
        testNftBrokeredBuyerBrokerCut();
        testDualFirewallSameCounterparty();
        testCounterpartySignaturesMalformed();
        testNftSellOnlyBuyerFirewall();
        testCheckCashTaggedPreauth();
        testPayChanOwnerCloseWithoutDestPreauth();
        testExpiredWithdrawNoauthUnderFirewall();
        testEscrowFinishAroundFirewall();
        testSoftBurnNeedsWithdrawAuth();
        testReserveSponsorNeedsCp();
        testSponsorshipSetCounterpartySponsorNeedsCp();
        testPayChanFundPreauthWithoutCp();
    }

    void
    testDelegateCannotBypass()
    {
        testcase("Delegate cannot bypass owner's Firewall dest policy, deny, or MaxAmount");
        using namespace jtx;

        Env env(*this);
        Account const alice{"alice"};
        Account const bob{"bob"};
        Account const carol{"carol"};
        Account const cp{"cp"};
        Account const backup{"backup"};
        Account const gw{"gw"};
        env.fund(XRP(10000), alice, bob, carol, cp, backup, gw);
        env.close();
        auto const USD = gw["USD"];
        env(trust(alice, USD(1000)));
        env.close();
        env(pay(gw, alice, USD(100)));
        env.close();
        arm(env, alice, cp, backup, /*maxFeeDrops=*/1'000'000, /*maxAmountDrops=*/5'000'000);

        // DelegateSet is allow-class (no CP). Permission names are stock TTs.
        env(delegate::set(alice, bob, {"Payment", "CheckCreate", "OfferCreate"}));
        env.close();

        // Unlisted dest: owner's Firewall, not the delegate's missing SLE.
        env(pay(alice, carol, XRP(1)), delegate::As(bob), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, carol, XRP(1)), delegate::As(bob), Sig(sfCounterpartySignature, cp));
        env.close();

        // Backup remains seed-alone (delegate may sign).
        env(pay(alice, backup, XRP(1)), delegate::As(bob));
        env.close();

        env(check::create(alice, carol, XRP(5)), delegate::As(bob), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(offer(alice, XRP(10), USD(10)), delegate::As(bob), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();

        // Deny is absolute even when a delegate signs, including with CP.
        env(fset(alice, asfWithdrawNoauth), Sig(sfCounterpartySignature, cp));
        env.close();
        env(withdrawauth::noauth(alice, carol), Sig(sfCounterpartySignature, cp));
        env.close();
        env(pay(alice, carol, XRP(1)), delegate::As(bob), Ter(tecFIREWALL_BLOCK));
        env.close();
        env(pay(alice, carol, XRP(1)),
            delegate::As(bob),
            Sig(sfCounterpartySignature, cp),
            Ter(tecFIREWALL_BLOCK));
        env.close();

        env(fclear(alice, asfWithdrawNoauth), Sig(sfCounterpartySignature, cp));
        env.close();

        // Daily cap: prior native pays already count. 5 XRP more exceeds 5 XRP MaxAmount.
        env(pay(alice, backup, XRP(5)), delegate::As(bob), Ter(tecREQUIRES_COUNTERPARTY));
        env.close();
        env(pay(alice, backup, XRP(5)), delegate::As(bob), Sig(sfCounterpartySignature, cp));
        env.close();
    }
};

BEAST_DEFINE_TESTSUITE(Firewall, app, xrpl);

}  // namespace xrpl::test
