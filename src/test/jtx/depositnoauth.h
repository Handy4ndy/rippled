#pragma once

#include <test/jtx/Account.h>
#include <test/jtx/Env.h>

#include <xrpl/json/json_value.h>

#include <cstdint>
#include <optional>

/** Deposit no-authorize operations */
namespace xrpl::test::jtx::depositnoauth {

json::Value
unauth(
    jtx::Account const& account,
    jtx::Account const& unauth,
    std::optional<std::uint32_t> expiration = std::nullopt);

json::Value
auth(jtx::Account const& account, jtx::Account const& auth);

}  // namespace xrpl::test::jtx::depositnoauth
