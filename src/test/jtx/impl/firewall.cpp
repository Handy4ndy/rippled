#include <test/jtx/firewall.h>

#include <xrpl/basics/base_uint.h>
#include <xrpl/json/json_value.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/jss.h>

namespace xrpl::test::jtx::firewall {

json::Value
setCreate(
    jtx::Account const& account,
    jtx::Account const& counterparty,
    jtx::Account const& backup,
    std::uint64_t maxFeeDrops,
    std::optional<std::uint32_t> backupTag,
    std::optional<std::uint64_t> maxAmountDrops)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::FirewallSet;
    jv[sfCounterparty.jsonName] = counterparty.human();
    jv[sfBackup.jsonName] = backup.human();
    jv[sfMaxFee.jsonName] = std::to_string(maxFeeDrops);
    if (backupTag)
        jv[sfDestinationTag.jsonName] = *backupTag;
    if (maxAmountDrops)
        jv[sfMaxAmount.jsonName] = std::to_string(*maxAmountDrops);
    return jv;
}

json::Value
setUpdateMaxFee(jtx::Account const& account, uint256 const& firewallId, std::uint64_t maxFeeDrops)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::FirewallSet;
    jv[sfFirewallID.jsonName] = to_string(firewallId);
    jv[sfMaxFee.jsonName] = std::to_string(maxFeeDrops);
    return jv;
}

json::Value
setUpdateMaxAmount(
    jtx::Account const& account,
    uint256 const& firewallId,
    std::uint64_t maxAmountDrops)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::FirewallSet;
    jv[sfFirewallID.jsonName] = to_string(firewallId);
    jv[sfMaxAmount.jsonName] = std::to_string(maxAmountDrops);
    return jv;
}

json::Value
del(jtx::Account const& account, uint256 const& firewallId, bool clearWithdrawLists)
{
    json::Value jv;
    jv[sfAccount.jsonName] = account.human();
    jv[sfTransactionType.jsonName] = jss::FirewallDelete;
    jv[sfFirewallID.jsonName] = to_string(firewallId);
    if (clearWithdrawLists)
        jv[sfFlags.jsonName] = tfClearWithdrawLists;
    return jv;
}

}  // namespace xrpl::test::jtx::firewall
