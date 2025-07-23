//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012-2014 Ripple Labs Inc.

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

#include <xrpld/app/ledger/LedgerMaster.h>
#include <xrpld/app/paths/TrustLine.h>
#include <xrpld/ledger/ReadView.h>
#include <xrpld/ledger/View.h>
#include <xrpld/rpc/Context.h>
#include <xrpld/rpc/detail/RPCHelpers.h>

#include <xrpl/json/json_value.h>
#include <xrpl/protocol/ErrorCodes.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/jss.h>

#include <new>

namespace ripple {

// {
//   command: "account_balance",
//   account: <account>,
//   ledger_hash : <ledger>
//   ledger_index : <ledger_index>
//   include_reserves: <bool>     // optional (default false)
//   include_trustlines: <bool>   // optional (default false)
// }

Json::Value
doAccountBalance(RPC::JsonContext& context)
{
    auto& params = context.params;

    // 1. Parameter Validation - Check for required account parameter
    if (!params.isMember(jss::account))
        return RPC::missing_field_error(jss::account);

    if (!params[jss::account].isString())
        return RPC::invalid_field_error(jss::account);

    std::string const strAccount = params[jss::account].asString();

    // 2. Account Validation - Parse and validate account format
    auto id = parseBase58<AccountID>(strAccount);
    if (!id)
    {
        Json::Value result;
        RPC::inject_error(rpcACT_MALFORMED, result);
        return result;
    }
    auto const accountID{std::move(id.value())};

    // 3. Ledger Access - Handle ledger selection
    std::shared_ptr<ReadView const> ledger;
    auto result = RPC::lookupLedger(ledger, context);
    
    if (!ledger)
        return result;

    // 4. Account Existence Check
    auto const sleAccount = ledger->read(keylet::account(accountID));
    if (!sleAccount)
    {
        result[jss::account] = strAccount;
        RPC::inject_error(rpcACT_NOT_FOUND, result);
        return result;
    }

    // 5. Parse optional parameters
    bool includeReserves = false;
    if (params.isMember("include_reserves"))
    {
        if (!params["include_reserves"].isBool())
            return RPC::invalid_field_error("include_reserves");
        includeReserves = params["include_reserves"].asBool();
    }

    bool includeTrustlines = false;
    if (params.isMember("include_trustlines"))
    {
        if (!params["include_trustlines"].isBool())
            return RPC::invalid_field_error("include_trustlines");
        includeTrustlines = params["include_trustlines"].asBool();
    }

    // 6. Build response
    result[jss::account] = strAccount;
    result[jss::ledger_index] = ledger->seq();

    // 7. Get XRP balance
    STAmount const balance = sleAccount->getFieldAmount(sfBalance);
    result["xrp_balance"] = balance.getText();

    // 8. Calculate reserves if requested
    if (includeReserves)
    {
        // Get reserve amounts from fees
        auto const fees = ledger->fees();
        auto const baseReserve = fees.base;
        auto const ownerReserve = fees.reserve;
        
        // Count owned objects for owner reserve calculation
        std::uint32_t ownerCount = sleAccount->getFieldU32(sfOwnerCount);
        auto const totalReserve = baseReserve + (ownerCount * ownerReserve);
        
        Json::Value reserves(Json::objectValue);
        reserves["base_reserve"] = to_string(baseReserve);
        reserves["owner_reserve"] = to_string(ownerReserve);
        reserves["total_reserve"] = to_string(totalReserve);
        
        result["reserves"] = std::move(reserves);
        
        // Calculate available balance (balance - total reserve)
        STAmount availableBalance = balance;
        if (balance >= totalReserve)
            availableBalance = balance - totalReserve;
        else
            availableBalance = STAmount{0};
            
        result["available_balance"] = availableBalance.getText();
    }
    else
    {
        // If reserves not requested, available balance equals total balance
        result["available_balance"] = balance.getText();
    }

    // 9. Include trustlines if requested
    if (includeTrustlines)
    {
        Json::Value trustlines(Json::arrayValue);
        
        // Iterate through account's trust lines using forEachItemAfter
        uint256 startAfter = beast::zero;
        std::uint64_t startHint = 0;
        unsigned int limit = 200; // Reasonable limit for trustlines
        
        forEachItemAfter(
            *ledger,
            accountID,
            startAfter,
            startHint,
            limit,
            [&trustlines, &accountID](std::shared_ptr<SLE const> const& sle) {
                if (!sle || sle->getType() != ltRIPPLE_STATE)
                    return true;

                auto const line = RPCTrustLine::makeItem(accountID, sle);
                if (line)
                {
                    Json::Value trustline(Json::objectValue);
                    STAmount const& balance = line->getBalance();
                    STAmount const& limit = line->getLimit();
                    
                    trustline[jss::account] = to_string(line->getAccountIDPeer());
                    trustline[jss::balance] = balance.getText();
                    trustline[jss::currency] = to_string(balance.issue().currency);
                    trustline[jss::limit] = limit.getText();
                    
                    trustlines.append(std::move(trustline));
                }
                
                return true;
            });
        
        result["trustlines"] = std::move(trustlines);
    }

    return result;
}

}  // namespace ripple
