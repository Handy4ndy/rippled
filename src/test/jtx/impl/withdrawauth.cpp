#include <test/jtx/withdrawauth.h>

#include <xrpl/json/json_value.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

#include <vector>

namespace xrpl::test::jtx::withdrawauth {

json::Value
auth(
    jtx::Account const& account,
    jtx::Account const& authorize,
    std::optional<std::uint32_t> destinationTag)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfAuthorize.jsonName] = authorize.human();
    if (destinationTag)
        jv[sfDestinationTag.jsonName] = *destinationTag;
    jv[sfTransactionType.jsonName] = jss::WithdrawPreauth;
    return jv;
}

json::Value
unauth(
    jtx::Account const& account,
    jtx::Account const& unauthorize,
    std::optional<std::uint32_t> destinationTag)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfUnauthorize.jsonName] = unauthorize.human();
    if (destinationTag)
        jv[sfDestinationTag.jsonName] = *destinationTag;
    jv[sfTransactionType.jsonName] = jss::WithdrawPreauth;
    return jv;
}

json::Value
noauth(
    jtx::Account const& account,
    jtx::Account const& unauthorize,
    std::optional<std::uint32_t> expiration)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfUnauthorize.jsonName] = unauthorize.human();
    if (expiration)
        jv[sfExpiration.jsonName] = *expiration;
    jv[sfTransactionType.jsonName] = jss::WithdrawNoauth;
    return jv;
}

json::Value
clearNoauth(jtx::Account const& account, jtx::Account const& authorize)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfAuthorize.jsonName] = authorize.human();
    jv[sfTransactionType.jsonName] = jss::WithdrawNoauth;
    return jv;
}

json::Value
setauth(jtx::Account const& account, std::vector<jtx::Account> const& providers, bool noauthList)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::WithdrawSetauth;
    jv[sfFlags.jsonName] = noauthList ? tfSetNoauthList : tfSetPreauthList;
    json::Value arr{json::ValueType::Array};
    for (auto const& p : providers)
    {
        json::Value inner;
        inner[sfAccount.jsonName] = p.human();
        json::Value wrap;
        wrap[sfDepositProvider.jsonName] = std::move(inner);
        arr.append(std::move(wrap));
    }
    jv[sfProviders.jsonName] = arr;
    return jv;
}

json::Value
clearSetauth(jtx::Account const& account, bool noauthList)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::WithdrawSetauth;
    jv[sfFlags.jsonName] = noauthList ? tfSetNoauthList : tfSetPreauthList;
    // absent Providers = delete
    return jv;
}

}  // namespace xrpl::test::jtx::withdrawauth
