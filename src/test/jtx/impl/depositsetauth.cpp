#include <test/jtx/depositsetauth.h>

#include <xrpl/json/json_value.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/jss.h>

namespace xrpl::test::jtx::depositsetauth {

json::Value
setauth(jtx::Account const& account, std::vector<jtx::Account> const& providers, bool noauthList)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::DepositSetauth;
    jv[sfFlags.jsonName] = noauthList ? 0x00010000u : 0x00020000u;
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
clear(jtx::Account const& account, bool noauthList)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::DepositSetauth;
    jv[sfFlags.jsonName] = noauthList ? 0x00010000u : 0x00020000u;
    return jv;
}

}  // namespace xrpl::test::jtx::depositsetauth
