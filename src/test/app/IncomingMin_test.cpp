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

#include <xrpl/beast/unit_test.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/TxFlags.h>

namespace ripple {
namespace test {

class IncomingMin_test : public beast::unit_test::suite
{
public:
    void
    testIncomingMin()
    {
        testcase("lsfMinPayment minimum amount enforcement");
        using namespace jtx;

        auto const alice = Account("alice");
        auto const bob = Account("bob");

        // Test with MinPayment flag set - payments below 2x base fee should fail
        {
            Env env(*this);
            env.fund(XRP(10000), alice, bob);

            std::cout << "[LOG] Funded alice and bob with 10000 XRP each\n";

            // Set MinPayment flag on bob's account
            env(fset(bob, asfMinPayment));
            std::cout << "[LOG] Set asfMinPayment flag on bob\n";

            // Get the base fee to calculate minimum amount
            auto const baseFee = env.current()->fees().base;
            auto const minAmountDrops = (baseFee * 2).drops();
            std::cout << "[LOG] baseFee: " << baseFee << ", minAmountDrops: " << minAmountDrops << "\n";

            // Payment below minimum should fail
            std::cout << "[LOG] Try payment below minimum: " << (minAmountDrops - 1) << " drops\n";
            env(pay(alice, bob, drops(minAmountDrops - 1)),
                ter(tecNO_PERMISSION));

            // Payment exactly at minimum should fail (must exceed, not equal)
            std::cout << "[LOG] Try payment at minimum: " << minAmountDrops << " drops\n";
            env(pay(alice, bob, drops(minAmountDrops)),
                ter(tecNO_PERMISSION));

            // Payment above minimum should succeed
            std::cout << "[LOG] Try payment above minimum: " << (minAmountDrops + 1) << " drops\n";
            env(pay(alice, bob, drops(minAmountDrops + 1)),
                ter(tesSUCCESS));
        }

        // Test with MinPayment flag NOT set - all payments should succeed
        {
            Env env(*this);
            env.fund(XRP(10000), alice, bob);

            std::cout << "[LOG] Funded alice and bob with 10000 XRP each (no MinPayment flag)\n";

            // Don't set MinPayment flag
            auto const baseFee = env.current()->fees().base;
            auto const minAmountDrops = (baseFee * 2).drops();
            std::cout << "[LOG] baseFee: " << baseFee << ", minAmountDrops: " << minAmountDrops << "\n";

            // Payment below what would be minimum should succeed
            std::cout << "[LOG] Try payment below minimum: " << (minAmountDrops - 1) << " drops\n";
            env(pay(alice, bob, drops(minAmountDrops - 1)),
                ter(tesSUCCESS));

            // Small payment should succeed
            std::cout << "[LOG] Try small payment: 1 drop\n";
            env(pay(alice, bob, drops(1)),
                ter(tesSUCCESS));
        }
    }

    void
    run() override
    {
        testIncomingMin();
    }
};

BEAST_DEFINE_TESTSUITE(IncomingMin, app, ripple);

}  // namespace test
}  // namespace ripple
