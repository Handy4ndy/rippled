#pragma once

#include <test/jtx/Account.h>

#include <xrpl/json/json_value.h>

#include <cstdint>
#include <optional>

namespace xrpl::test::jtx::firewall {

json::Value
setCreate(
    jtx::Account const& account,
    jtx::Account const& counterparty,
    jtx::Account const& backup,
    std::uint64_t maxFeeDrops,
    std::optional<std::uint32_t> backupTag = std::nullopt,
    std::optional<std::uint64_t> maxAmountDrops = std::nullopt);

json::Value
setUpdateMaxFee(jtx::Account const& account, uint256 const& firewallId, std::uint64_t maxFeeDrops);

json::Value
setUpdateMaxAmount(
    jtx::Account const& account,
    uint256 const& firewallId,
    std::uint64_t maxAmountDrops);

json::Value
del(jtx::Account const& account, uint256 const& firewallId, bool clearWithdrawLists = false);

}  // namespace xrpl::test::jtx::firewall
