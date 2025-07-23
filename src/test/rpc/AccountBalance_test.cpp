//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2016 Ripple Labs Inc.

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
#include <test/jtx/WSClient.h>

#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/jss.h>
#include <xrpld/rpc/detail/RPCHelpers.h>
#include <new>

namespace ripple {
namespace test {

class AccountBalance_test : public beast::unit_test::suite
{
public:
        
    void
    testBasicBalance()
    {
        testcase("Basic Balance");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        
        // Fund alice with 1000 XRP
        env.fund(XRP(1000), alice);
        env.close();

        // Test basic account_balance call without optional parameters
        auto const balance = env.rpc(
            "json",
            "account_balance",
            R"({ "account": ")" + alice.human() + R"("})");

        BEAST_EXPECT(balance[jss::result][jss::status] == "success");
        BEAST_EXPECT(balance[jss::result][jss::account] == alice.human());
        BEAST_EXPECT(balance[jss::result].isMember(jss::ledger_index));
        BEAST_EXPECT(balance[jss::result].isMember(jss::validated));
        BEAST_EXPECT(balance[jss::result].isMember("xrp_balance"));
        BEAST_EXPECT(balance[jss::result].isMember("available_balance"));
        
        // Should not include reserves or trustlines by default
        BEAST_EXPECT(!balance[jss::result].isMember("reserves"));
        BEAST_EXPECT(!balance[jss::result].isMember("trustlines"));
        
        // XRP balance should be 1000 XRP (1000000000 drops)
        BEAST_EXPECT(balance[jss::result]["xrp_balance"].asString() == "1000000000");
        // Available balance should equal XRP balance when reserves not calculated
        BEAST_EXPECT(balance[jss::result]["available_balance"].asString() == "1000000000");
    }

    void
    testReserveCalculation()
    {
        testcase("Reserve Calculation");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        
        env.fund(XRP(1000), alice);
        env.close();

        // Test with include_reserves = true
        auto const balance = env.rpc(
            "json",
            "account_balance",
            R"({ "account": ")" + alice.human() + R"(", "include_reserves": true })");

        BEAST_EXPECT(balance[jss::result][jss::status] == "success");
        BEAST_EXPECT(balance[jss::result].isMember("reserves"));
        
        auto const& reserves = balance[jss::result]["reserves"];
        BEAST_EXPECT(reserves.isMember("base_reserve"));
        BEAST_EXPECT(reserves.isMember("owner_reserve"));
        BEAST_EXPECT(reserves.isMember("total_reserve"));
        
        // Available balance should be less than total balance due to reserves
        auto const xrpBalance = balance[jss::result]["xrp_balance"].asString();
        auto const availableBalance = balance[jss::result]["available_balance"].asString();
        
        BEAST_EXPECT(xrpBalance == "1000000000");  // Total balance unchanged
        // Available should be total minus reserves (exact amount depends on reserve settings)
        BEAST_EXPECT(availableBalance != xrpBalance);
    }

    void
    testTrustlines()
    {
        testcase("Trustlines");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const gateway{"gateway"};
        
        env.fund(XRP(1000), alice, gateway);
        env.close();

        // Test without trustlines first
        {
            auto const balance = env.rpc(
                "json",
                "account_balance",
                R"({ "account": ")" + alice.human() + R"(", "include_trustlines": false })");
            
            BEAST_EXPECT(balance[jss::result][jss::status] == "success");
            BEAST_EXPECT(!balance[jss::result].isMember("trustlines"));
        }

        // Test with empty trustlines
        {
            auto const balance = env.rpc(
                "json",
                "account_balance",
                R"({ "account": ")" + alice.human() + R"(", "include_trustlines": true })");
            
            BEAST_EXPECT(balance[jss::result][jss::status] == "success");
            BEAST_EXPECT(balance[jss::result].isMember("trustlines"));
            BEAST_EXPECT(balance[jss::result]["trustlines"].isArray());
            BEAST_EXPECT(balance[jss::result]["trustlines"].size() == 0);
        }

        // Create a trust line
        auto const USD = gateway["USD"];
        env.trust(USD(1000), alice);
        env.close();
        
        env(pay(gateway, alice, USD(100)));
        env.close();

        // Test with trustlines after creating one
        {
            auto const balance = env.rpc(
                "json",
                "account_balance",
                R"({ "account": ")" + alice.human() + R"(", "include_trustlines": true })");
            
            BEAST_EXPECT(balance[jss::result][jss::status] == "success");
            BEAST_EXPECT(balance[jss::result].isMember("trustlines"));
            BEAST_EXPECT(balance[jss::result]["trustlines"].isArray());
            BEAST_EXPECT(balance[jss::result]["trustlines"].size() == 1);
            
            auto const& trustline = balance[jss::result]["trustlines"][0u];
            BEAST_EXPECT(trustline.isMember(jss::account));
            BEAST_EXPECT(trustline.isMember(jss::balance));
            BEAST_EXPECT(trustline.isMember(jss::currency));
            BEAST_EXPECT(trustline.isMember(jss::limit));
            
            BEAST_EXPECT(trustline[jss::account].asString() == gateway.human());
            BEAST_EXPECT(trustline[jss::currency].asString() == "USD");
        }
    }

    void
    testLedgerSpecification()
    {
        testcase("Ledger Specification");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        
        env.fund(XRP(1000), alice);
        env.close();

        // Test with different ledger specifications
        {
            // Test with "validated"
            auto const balance = env.rpc(
                "json",
                "account_balance",
                R"({ "account": ")" + alice.human() + R"(", "ledger_index": "validated" })");
            
            BEAST_EXPECT(balance[jss::result][jss::status] == "success");
            BEAST_EXPECT(balance[jss::result][jss::validated] == true);
        }
        {
            // Test with "current" 
            auto const balance = env.rpc(
                "json",
                "account_balance",
                R"({ "account": ")" + alice.human() + R"(", "ledger_index": "current" })");
            
            BEAST_EXPECT(balance[jss::result][jss::status] == "success");
        }
        {
            // Test with specific ledger index
            auto const currentLedger = env.current()->seq();
            auto const balance = env.rpc(
                "json",
                "account_balance",
                R"({ "account": ")" + alice.human() + R"(", "ledger_index": )" + 
                std::to_string(currentLedger) + R"( })");
            
            BEAST_EXPECT(balance[jss::result][jss::status] == "success");
            BEAST_EXPECT(balance[jss::result][jss::ledger_index] == currentLedger);
        }
    }

    void
    testCompleteResponse()
    {
        testcase("Complete Response");
        using namespace jtx;
        Env env(*this);
        Account const alice{"alice"};
        Account const gateway{"gateway"};
        
        env.fund(XRP(1000), alice, gateway);
        
        // Create trust line
        auto const USD = gateway["USD"];
        env.trust(USD(1000), alice);
        env(pay(gateway, alice, USD(100)));
        env.close();

        // Test with all options enabled
        auto const balance = env.rpc(
            "json",
            "account_balance",
            R"({ 
                "account": ")" + alice.human() + R"(", 
                "include_reserves": true,
                "include_trustlines": true,
                "ledger_index": "validated"
            })");

        BEAST_EXPECT(balance[jss::result][jss::status] == "success");
        
        // Check all required fields are present
        BEAST_EXPECT(balance[jss::result].isMember(jss::account));
        BEAST_EXPECT(balance[jss::result].isMember(jss::ledger_index));
        BEAST_EXPECT(balance[jss::result].isMember(jss::validated));
        BEAST_EXPECT(balance[jss::result].isMember("xrp_balance"));
        BEAST_EXPECT(balance[jss::result].isMember("available_balance"));
        BEAST_EXPECT(balance[jss::result].isMember("reserves"));
        BEAST_EXPECT(balance[jss::result].isMember("trustlines"));
        
        // Check reserves structure
        auto const& reserves = balance[jss::result]["reserves"];
        BEAST_EXPECT(reserves.isMember("base_reserve"));
        BEAST_EXPECT(reserves.isMember("owner_reserve"));
        BEAST_EXPECT(reserves.isMember("total_reserve"));
        
        // Check trustlines structure
        auto const& trustlines = balance[jss::result]["trustlines"];
        BEAST_EXPECT(trustlines.isArray());
        BEAST_EXPECT(trustlines.size() == 1);
    }

    void
    run() override
    {
        testBasicBalance();
        testReserveCalculation();
        testTrustlines();
        testLedgerSpecification();
        testCompleteResponse();
    }
};

BEAST_DEFINE_TESTSUITE(AccountBalance, rpc, ripple);

}  // namespace test
}  // namespace ripple
