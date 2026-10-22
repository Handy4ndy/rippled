#pragma once

#include <xrpl/basics/base_uint.h>
#include <xrpl/beast/utility/Journal.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFormats.h>
#include <xrpl/protocol/XRPAmount.h>

#include <cstdint>
#include <optional>

namespace xrpl {

class ApplyView;
class ReadView;
class STTx;

enum class FirewallAction : std::uint8_t {
    allow,
    check,
    block,
    manage,
    system,
};

FirewallAction
firewallActionFor(TxType tt);

bool
isPathingClassPayment(STTx const& tx);

struct DestInfo
{
    AccountID destination;
    std::uint32_t tag = 0;
    bool hasDestination = false;
};

DestInfo
extractFirewallDestination(STTx const& tx, ReadView const& view);

bool
hasFirewall(ReadView const& view, AccountID const& owner);

// sfAccount, not sfDelegate. A delegate signs and pays the fee.
AccountID
firewallValueSubject(STTx const& tx, ReadView const& view);

// temMALFORMED if both single and array present, array empty, or size > max.
NotTEC
preflightCounterpartySignatures(STTx const& tx, beast::Journal j);

TER
verifyCounterpartyCosign(
    ReadView const& view,
    STTx const& tx,
    AccountID const& counterparty,
    beast::Journal j);

TER
requireCounterpartyIfFirewalled(
    ReadView const& view,
    STTx const& tx,
    AccountID const& account,
    beast::Journal j);

bool
accountSetTouchesSealedFlags(STTx const& tx);

bool
accountSetTouchesKeySeal(STTx const& tx);

TER
checkFirewall(ReadView const& view, STTx const& tx, beast::Journal j);

// Extra Firewall/soft seals when the payer is not the primary subject:
// reserve sponsors, SponsorshipSet CounterpartySponsor, and NFT
// buy/brokered buyers (deny / WithdrawPreauth of payee / else CP).
TER
checkAdditionalValueSubjects(ReadView const& view, STTx const& tx, beast::Journal j);

XRPAmount
firewallNativeTransfer(STTx const& tx);

TER
applyFirewallAmountCap(ApplyView& view, STTx const& tx, beast::Journal j);

}  // namespace xrpl
