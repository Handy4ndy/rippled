#pragma once

#include <test/jtx/Account.h>
#include <test/jtx/Env.h>

#include <xrpl/json/json_value.h>

#include <optional>
#include <vector>

namespace xrpl::test::jtx::withdrawauth {

json::Value
auth(
    jtx::Account const& account,
    jtx::Account const& authorize,
    std::optional<std::uint32_t> destinationTag = std::nullopt);

json::Value
unauth(
    jtx::Account const& account,
    jtx::Account const& unauthorize,
    std::optional<std::uint32_t> destinationTag = std::nullopt);

json::Value
noauth(
    jtx::Account const& account,
    jtx::Account const& unauthorize,
    std::optional<std::uint32_t> expiration = std::nullopt);

json::Value
clearNoauth(jtx::Account const& account, jtx::Account const& authorize);

json::Value
setauth(jtx::Account const& account, std::vector<jtx::Account> const& providers, bool noauthList);

json::Value
clearSetauth(jtx::Account const& account, bool noauthList);

}  // namespace xrpl::test::jtx::withdrawauth
