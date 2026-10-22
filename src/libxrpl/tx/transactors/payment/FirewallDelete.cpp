#include <xrpl/tx/transactors/payment/FirewallDelete.h>

#include <xrpl/basics/Log.h>
#include <xrpl/beast/utility/Zero.h>
#include <xrpl/ledger/helpers/AccountRootHelpers.h>
#include <xrpl/ledger/helpers/DirectoryHelpers.h>
#include <xrpl/ledger/helpers/PaymentPolicyHelpers.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/tx/transactors/payment/WithdrawAuthorization.h>
#include <xrpl/tx/transactors/payment/WithdrawSetauth.h>

#include <vector>

namespace xrpl {

std::uint32_t
FirewallDelete::getFlagsMask(PreflightContext const&)
{
    return tfFirewallDeleteMask;
}

NotTEC
FirewallDelete::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureFirewall))
        return temDISABLED;

    if (!ctx.tx.isFieldPresent(sfFirewallID))
        return temMALFORMED;

    return tesSUCCESS;
}

TER
FirewallDelete::preclaim(PreclaimContext const& ctx)
{
    AccountID const account = ctx.tx.getAccountID(sfAccount);
    auto const fwKey = keylet::firewall(account);
    auto const sleFw = ctx.view.read(fwKey);
    if (!sleFw)
        return tecNO_TARGET;
    if (ctx.tx.getFieldH256(sfFirewallID) != fwKey.key)
        return tecNO_TARGET;
    if ((*sleFw)[sfOwner] != account)
        return tecNO_PERMISSION;

    AccountID const cp = (*sleFw)[sfCounterparty];
    return verifyCounterpartyCosign(ctx.view, ctx.tx, cp, ctx.j);
}

TER
FirewallDelete::doApply()
{
    auto const fwKey = keylet::firewall(accountID_);
    auto sleFw = view().peek(fwKey);
    if (!sleFw)
        return tecNO_TARGET;  // LCOV_EXCL_LINE

    // By default only the Firewall SLE is removed. Outbound withdraw lists that
    // the user created stay in place, and lsfWithdrawAuth is left set. Pass
    // tfClearWithdrawLists to also remove withdraw preauth/noauth/setauth
    // objects (the previous default behaviour).
    if (ctx_.tx.isFlag(tfClearWithdrawLists))
    {
        std::vector<uint256> toRemove;
        {
            Keylet const ownerDirKeylet{keylet::ownerDir(accountID_)};
            std::shared_ptr<SLE const> sleDirNode{};
            unsigned int uDirEntry{0};
            uint256 dirEntry{beast::kZero};
            if (cdirFirst(view(), ownerDirKeylet.key, sleDirNode, uDirEntry, dirEntry))
            {
                do
                {
                    auto const sleItem = view().read(keylet::child(dirEntry));
                    if (!sleItem)
                        continue;
                    auto const t = sleItem->getType();
                    if (t == ltWITHDRAW_PREAUTH || t == ltWITHDRAW_NOAUTH ||
                        t == ltWITHDRAW_SET_NOAUTH || t == ltWITHDRAW_SET_PREAUTH)
                        toRemove.push_back(dirEntry);
                } while (cdirNext(view(), ownerDirKeylet.key, sleDirNode, uDirEntry, dirEntry));
            }
        }

        for (auto const& idx : toRemove)
        {
            auto const sle = view().read(keylet::unchecked(idx));
            if (!sle)
                continue;
            switch (sle->getType())
            {
                case ltWITHDRAW_PREAUTH:
                    if (auto const ter =
                            WithdrawAuthorization::removePreauthFromLedger(view(), idx, j_);
                        !isTesSuccess(ter))
                        return ter;
                    break;
                case ltWITHDRAW_NOAUTH:
                    if (auto const ter =
                            WithdrawAuthorization::removeNoauthFromLedger(view(), idx, j_);
                        !isTesSuccess(ter))
                        return ter;
                    break;
                case ltWITHDRAW_SET_NOAUTH:
                    if (auto const ter =
                            WithdrawSetauth::removeSetNoauthFromLedger(view(), idx, j_);
                        !isTesSuccess(ter))
                        return ter;
                    break;
                case ltWITHDRAW_SET_PREAUTH:
                    if (auto const ter =
                            WithdrawSetauth::removeSetPreauthFromLedger(view(), idx, j_);
                        !isTesSuccess(ter))
                        return ter;
                    break;
                default:
                    break;
            }
        }
    }

    AccountID const owner{(*sleFw)[sfOwner]};
    std::uint64_t const page{(*sleFw)[sfOwnerNode]};
    if (!view().dirRemove(keylet::ownerDir(owner), page, fwKey.key, false))
    {
        // LCOV_EXCL_START
        JLOG(j_.fatal()) << "Unable to delete Firewall from owner directory.";
        return tefBAD_LEDGER;
        // LCOV_EXCL_STOP
    }

    auto sleOwner = view().peek(keylet::account(owner));
    if (!sleOwner)
        return tefINTERNAL;  // LCOV_EXCL_LINE

    decreaseOwnerCountForObject(view(), sleOwner, sleFw, 1, j_);
    view().erase(sleFw);
    return tesSUCCESS;
}

void
FirewallDelete::visitInvariantEntry(bool, SLE::ConstRef, SLE::ConstRef)
{
}

bool
FirewallDelete::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
