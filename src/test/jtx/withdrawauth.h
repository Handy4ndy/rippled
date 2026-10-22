#pragma once

#include <test/jtx/Account.h>
#include <test/jtx/Env.h>

#include <xrpl/json/json_value.h>

#include <optional>
#include <vector>

/** Withdraw allow/deny jtx helpers (featurePaymentPolicy). */
namespace xrpl::test::jtx::withdrawauth {

/** Add WithdrawPreauth (allow outgoing payments to auth, optional DestTag). */
json::Value
auth(
    jtx::Account const& account,
    jtx::Account const& authorize,
    std::optional<std::uint32_t> destinationTag = std::nullopt);

/** Remove WithdrawPreauth (must match DestTag used at create). */
json::Value
unauth(
    jtx::Account const& account,
    jtx::Account const& unauthorize,
    std::optional<std::uint32_t> destinationTag = std::nullopt);

/** Add WithdrawNoauth (deny outgoing payments to unauth). */
json::Value
noauth(jtx::Account const& account, jtx::Account const& unauthorize,
    std::optional<std::uint32_t> expiration = std::nullopt);

/** Remove WithdrawNoauth. */
json::Value
clearNoauth(jtx::Account const& account, jtx::Account const& authorize);

/** WithdrawSetauth — set/replace provider list (tfSetNoauthList or tfSetPreauthList). */
json::Value
setauth(
    jtx::Account const& account,
    std::vector<jtx::Account> const& providers,
    bool noauthList);

/** WithdrawSetauth — delete provider list SLE. */
json::Value
clearSetauth(jtx::Account const& account, bool noauthList);

}  // namespace xrpl::test::jtx::withdrawauth
