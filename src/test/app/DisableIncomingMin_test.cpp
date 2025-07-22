//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2023 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <test/jtx.h>

#include <xrpld/app/tx/applySteps.h>
#include <xrpld/ledger/Dir.h>

#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <algorithm>
#include <chrono>
#include <iterator>

namespace ripple {
namespace test {

class IncomingMin_test : public beast::unit_test::suite
{
public:
    void
    testIncomingMin()
    {
        testcase("asfDisallowIncomingMinimum minimum amount enforcement");
        using namespace jtx;

        auto const alice = Account("alice");
        auto const bob = Account("bob");

        // Test with flag set - payments below base fee should fail
        {
            Env env(*this);
            env.fund(XRP(10000), alice, bob);

            env(fset(bob, asfDisallowIncomingMinimum));

            auto const baseFee = env.current()->fees().base;
            auto const minAmountDrops = baseFee.drops();

            env(pay(alice, bob, drops(minAmountDrops - 1)),
                ter(tecNO_PERMISSION));
            env(pay(alice, bob, drops(minAmountDrops)), ter(tecNO_PERMISSION));
            env(pay(alice, bob, drops(minAmountDrops + 1)), ter(tesSUCCESS));
        }

        // Test with flag NOT set - all payments should succeed
        {
            Env env(*this);
            env.fund(XRP(10000), alice, bob);

            auto const baseFee = env.current()->fees().base;
            auto const minAmountDrops = baseFee.drops();

            env(pay(alice, bob, drops(minAmountDrops - 1)), ter(tesSUCCESS));
            env(pay(alice, bob, drops(1)), ter(tesSUCCESS));
        }
    }

    // void
    // testFeeEscalation()
    // {
    //     using namespace jtx;
    //     testcase("TODO::Minimum enforcement during fee escalation");

    //     // auto const alice = Account("alice");
    //     // auto const bob = Account("bob");

    //     // // Simulate normal fee
    //     // {
    //     //     Env env(*this);
    //     //     env.fund(XRP(10000), alice, bob);
    //     //     env(fset(bob, asfDisallowIncomingMinimum));
    //     //     auto const baseFee = env.current()->fees().base;
    //     //     auto const minAmountDrops = baseFee.drops();
    //     //     env(pay(alice, bob, drops(minAmountDrops)), -1), ter(tecNO_PERMISSION);
    //     //     env(pay(alice, bob, drops(minAmountDrops)), ter(tecNO_PERMISSION));
    //     //     env(pay(alice, bob, drops(minAmountDrops)) + 1), ter(tesSUCCESS);
    //     // }

    //     // // Simulate fee escalation (base fee doubled)
    //     // {
    //     //     Env env(*this);
    //     //     env.fund(XRP(10000), alice, bob);
    //     //     env(fset(bob, asfDisallowIncomingMinimum));
    //     //     auto const baseFee = env.current()->fees().base;
    //     //     auto const minAmountDrops = baseFee.drops();
    //     //     env(pay(alice, bob, drops(minAmountDrops)), -1), ter(tecNO_PERMISSION);
    //     //     env(pay(alice, bob, drops(minAmountDrops)), ter(tecNO_PERMISSION));
    //     //     env(pay(alice, bob, drops(minAmountDrops)) + 1), ter(tesSUCCESS);
    //     // }

    //     // // Simulate fee escalation (base fee tripled)
    //     // {
    //     //     Env env(*this);
    //     //     env.fund(XRP(10000), alice, bob);
    //     //     env(fset(bob, asfDisallowIncomingMinimum));
    //     //     auto const baseFee = env.current()->fees().base;
    //     //     auto const minAmountDrops = baseFee.drops();
    //     //     env(pay(alice, bob, drops(minAmountDrops)), -1), ter(tecNO_PERMISSION);
    //     //     env(pay(alice, bob, drops(minAmountDrops)), ter(tecNO_PERMISSION));
    //     //     env(pay(alice, bob, drops(minAmountDrops)) + 1), ter(tesSUCCESS);
    //     // }
    // }

    void
    testSetRegularKey()
    {
        using namespace jtx;
        testcase("asfDisallowIncomingMinimum does NOT block SetRegularKey");

        auto const alice = Account("alice");
        auto const bob = Account("bob");
        auto const regKey = Account("regKey");

        Env env(*this);
        env.fund(XRP(10000), alice, bob, regKey);

        env(fset(bob, asfDisallowIncomingMinimum));
        env(regkey(bob, regKey), ter(tesSUCCESS));
        env(fclear(bob, asfDisallowIncomingMinimum));
        env(regkey(bob, regKey), ter(tesSUCCESS));
    }

    void
    testIncomingMinimumEscrow()
    {
        testcase("asfDisallowIncomingMinimum does NOT block XRP Escrow");

        using namespace jtx;
        using namespace std::chrono;

        {
            Env env(*this);
            auto const baseFee = env.current()->fees().base * 2;
            env.fund(XRP(5000), "bob", "george");
            env(fset("george", asfDisallowIncomingMinimum));
            env(escrow::create("bob", "george", XRP(baseFee.drops() - 1)),
                escrow::finish_time(env.now() + 1s),
                ter(tesSUCCESS));
        }
        {
            Env env(*this);
            auto const baseFee = env.current()->fees().base;
            env.fund(XRP(5000), "bob", "george");
            env(fset("bob", asfDisallowIncomingMinimum));
            env(escrow::create("bob", "george", XRP(baseFee.drops() - 1)),
                escrow::finish_time(env.now() + 1s),
                ter(tesSUCCESS));
        }
    }

    void
    run() override
    {
        testIncomingMin();
        // testFeeEscalation();
        testSetRegularKey();
        testIncomingMinimumEscrow();
    }
};

BEAST_DEFINE_TESTSUITE(IncomingMin, app, ripple);

}  // namespace test
}  // namespace ripple