//------------------------------------------------------------------------------
/*
    Soft Payment Policy coverage for Loan value exits
    (CoverDeposit / CoverWithdraw / LoanPay).
    Hooks live in the Loan* transactors; this suite asserts WithdrawAuth U-exit /
    dest gating without pulling the full Loan lifecycle fuzzer surface.
*/
//==============================================================================

#include <test/jtx/Account.h>
#include <test/jtx/Env.h>
#include <test/jtx/TestHelpers.h>
#include <test/jtx/amount.h>
#include <test/jtx/fee.h>
#include <test/jtx/flags.h>
#include <test/jtx/pay.h>
#include <test/jtx/sig.h>
#include <test/jtx/ter.h>
#include <test/jtx/trust.h>
#include <test/jtx/vault.h>
#include <test/jtx/withdrawauth.h>

#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/SeqProxy.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>

namespace xrpl::test {

struct LoanPaymentPolicy_test : public beast::unit_test::Suite
{
    // Match LoanBroker_test: LendingProtocol depends on SAV; leave V1_1/V1_2 off
    // so CoverDeposit/Withdraw / LoanPay exercise the baseline LoanBroker mechanics.
    FeatureBitset const all_{
        jtx::testableAmendments() - featureLendingProtocolV1_1 - featureLendingProtocolV1_2,
    };

    void
    testCoverDepositWithdrawAuth()
    {
        testcase("Soft PP: LoanBrokerCoverDeposit is U-exit under WithdrawAuth");
        using namespace jtx;
        using namespace loan_broker;

        Env env(*this, all_);
        Vault const vault{env};
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        env.fund(XRP(100'000), issuer, alice);
        env(trust(alice, issuer["IOU"](1'000'000)));
        env.close();
        PrettyAsset const asset(issuer["IOU"]);
        env(pay(issuer, alice, asset(100'000)));
        env.close();

        auto [tx, vaultKeylet] = vault.create({.owner = alice, .asset = asset});
        env(tx);
        env(vault.deposit({.depositor = alice, .id = vaultKeylet.key, .amount = asset(50)}));
        env.close();

        auto const brokerKeylet =
            keylet::loanBroker(alice.id(), SeqProxy::rawSequence(env.seq(alice)));
        env(set(alice, vaultKeylet.key));
        env.close();
        if (!BEAST_EXPECT(env.le(brokerKeylet)))
            return;

        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(coverDeposit(alice, brokerKeylet.key, asset(10)), Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        env(coverDeposit(alice, brokerKeylet.key, asset(10)));
        env.close();
    }

    void
    testCoverWithdrawDestPolicy()
    {
        testcase("Soft PP: LoanBrokerCoverWithdraw directed dest needs WithdrawPreauth");
        using namespace jtx;
        using namespace loan_broker;

        Env env(*this, all_);
        Vault const vault{env};
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        Account const bob{"bob"};
        env.fund(XRP(100'000), issuer, alice, bob);
        env(trust(alice, issuer["IOU"](1'000'000)));
        env(trust(bob, issuer["IOU"](1'000'000)));
        env.close();
        PrettyAsset const asset(issuer["IOU"]);
        env(pay(issuer, alice, asset(100'000)));
        env.close();

        auto [tx, vaultKeylet] = vault.create({.owner = alice, .asset = asset});
        env(tx);
        env(vault.deposit({.depositor = alice, .id = vaultKeylet.key, .amount = asset(50)}));
        env.close();

        auto const brokerKeylet =
            keylet::loanBroker(alice.id(), SeqProxy::rawSequence(env.seq(alice)));
        env(set(alice, vaultKeylet.key));
        env.close();
        if (!BEAST_EXPECT(env.le(brokerKeylet)))
            return;

        env(coverDeposit(alice, brokerKeylet.key, asset(20)));
        env.close();

        env(fset(alice, asfWithdrawAuth));
        env.close();
        // Self withdraw is U-exit under WithdrawAuth.
        env(coverWithdraw(alice, brokerKeylet.key, asset(1)), Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(alice, asfWithdrawAuth));
        env.close();
        env(coverWithdraw(alice, brokerKeylet.key, asset(1)));
        env.close();

        // Directed withdraw: re-arm and require bob preauth.
        env(fset(alice, asfWithdrawAuth));
        env.close();
        env(coverWithdraw(alice, brokerKeylet.key, asset(1)),
            kDestination(bob),
            Ter(tecNO_PERMISSION));
        env.close();
        env(withdrawauth::auth(alice, bob));
        env.close();
        env(coverWithdraw(alice, brokerKeylet.key, asset(1)), kDestination(bob));
        env.close();
    }

    void
    testLoanPayWithdrawAuth()
    {
        testcase("Soft PP: LoanPay is U-exit under WithdrawAuth");
        using namespace jtx;
        using namespace loan_broker;

        Env env(*this, all_);
        Vault const vault{env};
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        Account const borrower{"borrower"};
        env.fund(XRP(100'000), issuer, alice, borrower);
        env(trust(alice, issuer["IOU"](1'000'000)));
        env(trust(borrower, issuer["IOU"](1'000'000)));
        env.close();
        PrettyAsset const asset(issuer["IOU"]);
        env(pay(issuer, alice, asset(100'000)));
        env.close();

        auto [tx, vaultKeylet] = vault.create({.owner = alice, .asset = asset});
        env(tx);
        env(vault.deposit({.depositor = alice, .id = vaultKeylet.key, .amount = asset(50)}));
        env.close();

        auto const brokerKeylet =
            keylet::loanBroker(alice.id(), SeqProxy::rawSequence(env.seq(alice)));
        env(set(alice, vaultKeylet.key));
        env.close();
        if (!BEAST_EXPECT(env.le(brokerKeylet)))
            return;

        auto const loanKeylet = keylet::loan(brokerKeylet.key, SeqProxy::rawSequence(1));
        env(loan::set(borrower, brokerKeylet.key, asset(10).value()),
            Sig(sfCounterpartySignature, alice),
            Fee(env.current()->fees().base * 2));
        env.close();
        if (!BEAST_EXPECT(env.le(loanKeylet)))
            return;

        env(fset(borrower, asfWithdrawAuth));
        env.close();
        env(loan::pay(borrower, loanKeylet.key, asset(10).value()), Ter(tecNO_PERMISSION));
        env.close();

        env(fclear(borrower, asfWithdrawAuth));
        env.close();
        env(loan::pay(borrower, loanKeylet.key, asset(10).value()));
        env.close();
    }

    void
    testLoanSetHybridCounterpartySigs()
    {
        testcase("LoanSet accepts hybrid CounterpartySignatures for broker cosign");
        using namespace jtx;
        using namespace loan_broker;

        Env env(*this, all_);
        Vault const vault{env};
        Account const issuer{"issuer"};
        Account const alice{"alice"};
        Account const borrower{"borrower"};
        env.fund(XRP(100'000), issuer, alice, borrower);
        env(trust(alice, issuer["IOU"](1'000'000)));
        env(trust(borrower, issuer["IOU"](1'000'000)));
        env.close();
        PrettyAsset const asset(issuer["IOU"]);
        env(pay(issuer, alice, asset(100'000)));
        env.close();

        auto [tx, vaultKeylet] = vault.create({.owner = alice, .asset = asset});
        env(tx);
        env(vault.deposit({.depositor = alice, .id = vaultKeylet.key, .amount = asset(50)}));
        env.close();

        auto const brokerKeylet =
            keylet::loanBroker(alice.id(), SeqProxy::rawSequence(env.seq(alice)));
        env(set(alice, vaultKeylet.key));
        env.close();
        if (!BEAST_EXPECT(env.le(brokerKeylet)))
            return;

        auto const loanKeylet = keylet::loan(brokerKeylet.key, SeqProxy::rawSequence(1));
        auto const base = env.current()->fees().base;
        env(loan::set(borrower, brokerKeylet.key, asset(5).value()), CpSigs{alice}, Fee(base * 2));
        env.close();
        BEAST_EXPECT(env.le(loanKeylet));
    }

    void
    run() override
    {
        testCoverDepositWithdrawAuth();
        testCoverWithdrawDestPolicy();
        testLoanPayWithdrawAuth();
        testLoanSetHybridCounterpartySigs();
    }
};

BEAST_DEFINE_TESTSUITE(LoanPaymentPolicy, app, xrpl);

}  // namespace xrpl::test
