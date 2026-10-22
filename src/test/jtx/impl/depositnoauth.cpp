#include <test/jtx/depositnoauth.h>

#include <xrpl/json/json_value.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/jss.h>

namespace xrpl::test::jtx::depositnoauth {

json::Value
unauth(
    jtx::Account const& account,
    jtx::Account const& unauth,
    std::optional<std::uint32_t> expiration)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfUnauthorize.jsonName] = unauth.human();
    if (expiration)
        jv[sfExpiration.jsonName] = *expiration;
    jv[sfTransactionType.jsonName] = jss::DepositNoauth;
    return jv;
}

json::Value
auth(jtx::Account const& account, jtx::Account const& auth)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfAuthorize.jsonName] = auth.human();
    jv[sfTransactionType.jsonName] = jss::DepositNoauth;
    return jv;
}

}  // namespace xrpl::test::jtx::depositnoauth
