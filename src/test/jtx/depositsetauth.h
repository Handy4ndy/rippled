#pragma once

#include <test/jtx/Account.h>

#include <xrpl/json/json_value.h>

#include <vector>

namespace xrpl::test::jtx::depositsetauth {

json::Value
setauth(jtx::Account const& account, std::vector<jtx::Account> const& providers, bool noauthList);

json::Value
clear(jtx::Account const& account, bool noauthList);

}  // namespace xrpl::test::jtx::depositsetauth
